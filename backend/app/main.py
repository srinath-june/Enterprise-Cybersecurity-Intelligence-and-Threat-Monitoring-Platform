import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.audit import append_audit, verify_chain
from app.database import Base, create_session_factory
from app.detection import evaluate_event
from app.models import AuditRecord, Incident, LogEvent, User, utc_now
from app.schemas import (
    AuditOut,
    EventIn,
    EventOut,
    IncidentDetail,
    IncidentOut,
    IncidentStatusUpdate,
    LoginRequest,
    TokenOut,
    UserOut,
)
from app.security import create_access_token, get_current_user, hash_password, require_roles, verify_password


def _incident_out(incident: Incident) -> IncidentOut:
    return IncidentOut(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        rule_key=incident.rule_key,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        event_count=len(incident.events),
    )


def _seed_demo_data(session: Session) -> None:
    now = utc_now()
    brute_force = Incident(
        title="Repeated authentication failures",
        description="Five failed login attempts for jdoe from 203.0.113.42 within ten minutes.",
        severity="high",
        risk_score=80,
        rule_key="auth_bruteforce",
        created_at=now - timedelta(minutes=3),
    )
    malware = Incident(
        title="Malware detected",
        description="A malware detection event requires immediate investigation. Host: finance-07. Account: svc-backup.",
        severity="critical",
        risk_score=98,
        rule_key="malware_detected",
        created_at=now - timedelta(minutes=17),
    )
    session.add_all([brute_force, malware])
    session.flush()
    for index in range(5):
        session.add(
            LogEvent(
                timestamp=now - timedelta(minutes=5 - index),
                source="identity-provider",
                host="auth-01",
                username="jdoe",
                event_type="authentication_failure",
                source_ip="203.0.113.42",
                severity="medium",
                message="Invalid password",
                incident=brute_force,
            )
        )
    session.add(
        LogEvent(
            timestamp=now - timedelta(minutes=17),
            source="endpoint-agent",
            host="finance-07",
            username="svc-backup",
            event_type="malware_detected",
            source_ip="10.0.8.17",
            severity="critical",
            message="Quarantined suspicious executable",
            incident=malware,
        )
    )
    session.add(
        LogEvent(
            timestamp=now - timedelta(minutes=1),
            source="web-gateway",
            host="web-02",
            username="analyst",
            event_type="normal",
            source_ip="10.0.2.15",
            severity="low",
            message="Successful authenticated session",
        )
    )


def create_app(
    database_url: str | None = None,
    *,
    secret_key: str | None = None,
    bootstrap_admin_email: str | None = None,
    bootstrap_admin_password: str | None = None,
    seed_demo_data: bool | None = None,
) -> FastAPI:
    engine, session_factory = create_session_factory(database_url)
    app_secret = secret_key or os.getenv("SECRET_KEY", "development-only-change-me")
    admin_email = (bootstrap_admin_email or os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@sentinel.local")).lower()
    admin_password = bootstrap_admin_password or os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "demo-password")
    should_seed = seed_demo_data
    if should_seed is None:
        should_seed = os.getenv("SEED_DEMO_DATA", "true").lower() == "true"
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        Base.metadata.create_all(engine)
        with session_factory() as session:
            if session.scalar(select(User).where(User.email == admin_email)) is None:
                session.add(
                    User(
                        email=admin_email,
                        password_hash=hash_password(admin_password),
                        role="admin",
                    )
                )
            if should_seed and session.scalar(select(LogEvent.id).limit(1)) is None:
                _seed_demo_data(session)
            session.commit()
        yield
        engine.dispose()

    application = FastAPI(
        title="Sentinel Security Intelligence API",
        version="0.1.0",
        description="Defensive log ingestion, rule-based detections, incident response, and audit verification.",
        lifespan=lifespan,
    )
    application.state.session_factory = session_factory
    application.state.secret_key = app_secret
    origins = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if origin.strip()
    ]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

    def get_db(request: Request):
        with request.app.state.session_factory() as session:
            yield session

    DbSession = Annotated[Session, Depends(get_db)]
    CurrentUser = Annotated[User, Depends(get_current_user)]
    Analyst = Annotated[User, Depends(require_roles("analyst", "admin"))]
    Admin = Annotated[User, Depends(require_roles("admin"))]

    @application.get("/api/health")
    def health():
        return {"status": "ok"}

    @application.post("/api/auth/login", response_model=TokenOut)
    def login(payload: LoginRequest, request: Request, session: DbSession):
        user = session.scalar(
            select(User).where(User.email == payload.email.lower(), User.is_active.is_(True))
        )
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_access_token(user, request.app.state.secret_key)
        append_audit(session, user, "auth.login", "user", str(user.id))
        session.commit()
        return TokenOut(access_token=token, user=user)

    @application.get("/api/auth/me", response_model=UserOut)
    def me(user: CurrentUser):
        return user

    @application.get("/api/summary")
    def summary(session: DbSession, _: CurrentUser):
        incident_counts = {
            row[0]: row[1]
            for row in session.execute(
                select(Incident.severity, func.count(Incident.id)).where(
                    Incident.status != "resolved"
                ).group_by(Incident.severity)
            )
        }
        total_open = session.scalar(
            select(func.count(Incident.id)).where(Incident.status != "resolved")
        ) or 0
        events_24h = session.scalar(
            select(func.count(LogEvent.id)).where(
                LogEvent.timestamp >= utc_now() - timedelta(hours=24)
            )
        ) or 0
        events = session.scalars(
            select(LogEvent).order_by(LogEvent.timestamp.desc()).limit(8)
        )
        return {
            "open_incidents": total_open,
            "critical_incidents": incident_counts.get("critical", 0),
            "high_incidents": incident_counts.get("high", 0),
            "events_24h": events_24h,
            "recent_events": [EventOut.model_validate(event) for event in events],
        }

    @application.get("/api/incidents", response_model=list[IncidentOut])
    def list_incidents(
        session: DbSession,
        _: CurrentUser,
        incident_status: str | None = Query(default=None, alias="status"),
        severity: str | None = None,
        search: str | None = Query(default=None, max_length=120),
        limit: int = Query(default=100, ge=1, le=200),
    ):
        query = select(Incident).options(selectinload(Incident.events))
        if incident_status:
            if incident_status not in {"open", "investigating", "resolved"}:
                raise HTTPException(status_code=422, detail="Unsupported incident status")
            query = query.where(Incident.status == incident_status)
        if severity:
            if severity not in {"low", "medium", "high", "critical"}:
                raise HTTPException(status_code=422, detail="Unsupported severity")
            query = query.where(Incident.severity == severity)
        if search:
            query = query.where(
                Incident.title.ilike(f"%{search}%")
                | Incident.description.ilike(f"%{search}%")
            )
        incidents = session.scalars(
            query.order_by(Incident.created_at.desc()).limit(limit)
        )
        return [_incident_out(incident) for incident in incidents]

    @application.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
    def incident_detail(incident_id: int, session: DbSession, _: CurrentUser):
        incident = session.scalar(
            select(Incident)
            .where(Incident.id == incident_id)
            .options(selectinload(Incident.events))
        )
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return IncidentDetail(
            **_incident_out(incident).model_dump(),
            events=[
                EventOut.model_validate(event)
                for event in sorted(incident.events, key=lambda item: item.timestamp)
            ],
        )

    @application.patch("/api/incidents/{incident_id}", response_model=IncidentOut)
    def update_incident(
        incident_id: int,
        payload: IncidentStatusUpdate,
        session: DbSession,
        user: Analyst,
    ):
        incident = session.scalar(
            select(Incident)
            .where(Incident.id == incident_id)
            .options(selectinload(Incident.events))
        )
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident.status = payload.status
        incident.updated_at = utc_now()
        append_audit(
            session, user, "incident.status_changed", "incident", str(incident.id)
        )
        session.commit()
        return _incident_out(incident)

    @application.post("/api/events", response_model=list[EventOut], status_code=201)
    def ingest_events(
        payload: list[EventIn],
        session: DbSession,
        user: Analyst,
    ):
        if not payload or len(payload) > 500:
            raise HTTPException(
                status_code=422, detail="Provide between 1 and 500 events per request"
            )
        created: list[LogEvent] = []
        for event_input in payload:
            values = event_input.model_dump()
            if values["timestamp"].tzinfo is None:
                from datetime import timezone

                values["timestamp"] = values["timestamp"].replace(tzinfo=timezone.utc)
            event = LogEvent(**values)
            session.add(event)
            session.flush()
            evaluate_event(session, event)
            created.append(event)
        append_audit(
            session, user, "events.ingested", "log_event", str(len(created))
        )
        session.commit()
        return [EventOut.model_validate(event) for event in created]

    @application.get("/api/audit", response_model=list[AuditOut])
    def list_audit(
        session: DbSession,
        _: Admin,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        records = session.scalars(
            select(AuditRecord).order_by(AuditRecord.id.desc()).limit(limit)
        )
        return list(records)

    @application.get("/api/audit/verify")
    def audit_verify(session: DbSession, _: Admin):
        records = list(session.scalars(select(AuditRecord).order_by(AuditRecord.id)))
        valid = verify_chain(records)
        return {"valid": valid, "records_checked": len(records)}

    return application


app = create_app()

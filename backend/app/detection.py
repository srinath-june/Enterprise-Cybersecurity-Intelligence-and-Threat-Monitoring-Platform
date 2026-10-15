from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Incident, LogEvent

AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW = timedelta(minutes=10)

SIGNAL_RULES = {
    "suspicious_login": (
        "high",
        82,
        "Suspicious login detected",
        "A login event was marked suspicious and requires analyst review.",
    ),
    "malware_detected": (
        "critical",
        98,
        "Malware detected",
        "A malware detection event requires immediate investigation.",
    ),
    "privilege_escalation": (
        "critical",
        95,
        "Possible privilege escalation",
        "A privilege escalation event requires immediate investigation.",
    ),
}


def evaluate_event(session: Session, event: LogEvent) -> Incident | None:
    signal = SIGNAL_RULES.get(event.event_type)
    if signal:
        severity, score, title, description = signal
        incident = Incident(
            title=title,
            description=f"{description} Host: {event.host}. Account: {event.username or 'unknown'}.",
            severity=severity,
            risk_score=score,
            rule_key=event.event_type,
        )
        session.add(incident)
        session.flush()
        event.incident = incident
        return incident

    if (
        event.event_type != "authentication_failure"
        or not event.username
        or not event.source_ip
    ):
        return None

    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    cutoff = timestamp - AUTH_FAILURE_WINDOW
    failures = list(
        session.scalars(
            select(LogEvent).where(
                LogEvent.event_type == "authentication_failure",
                LogEvent.username == event.username,
                LogEvent.source_ip == event.source_ip,
                LogEvent.timestamp >= cutoff,
            )
        )
    )
    if len(failures) < AUTH_FAILURE_THRESHOLD:
        return None

    incident = session.scalar(
        select(Incident)
        .where(Incident.rule_key == "auth_bruteforce", Incident.status != "resolved")
        .order_by(Incident.id.desc())
        .limit(1)
    )
    if incident is None:
        incident = Incident(
            title="Repeated authentication failures",
            description=(
                f"{len(failures)} failed login attempts for {event.username} from "
                f"{event.source_ip} within ten minutes."
            ),
            severity="high",
            risk_score=80,
            rule_key="auth_bruteforce",
        )
        session.add(incident)
        session.flush()
    for failure in failures:
        failure.incident = incident
    return incident

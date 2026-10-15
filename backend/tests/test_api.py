from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import create_app
from app.models import AuditRecord, User
from app.security import hash_password


def build_client():
    application = create_app(
        "sqlite://",
        secret_key="test-secret",
        bootstrap_admin_email="admin@test.local",
        bootstrap_admin_password="test-password",
        seed_demo_data=False,
    )
    return application, TestClient(application)


def login(client: TestClient) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "test-password"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_repeated_authentication_failures_create_timeline_and_audit():
    application, client = build_client()
    with client:
        token = login(client)
        timestamp = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (timestamp - timedelta(minutes=4 - index)).isoformat(),
                "source": "identity-provider",
                "host": "auth-01",
                "username": "jdoe",
                "event_type": "authentication_failure",
                "source_ip": "203.0.113.42",
                "severity": "medium",
                "message": "Invalid password",
            }
            for index in range(5)
        ]
        response = client.post(
            "/api/events",
            json=events,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201

        incidents = client.get(
            "/api/incidents", headers={"Authorization": f"Bearer {token}"}
        )
        assert incidents.status_code == 200
        assert len(incidents.json()) == 1
        incident = incidents.json()[0]
        assert incident["rule_key"] == "auth_bruteforce"
        assert incident["event_count"] == 5

        detail = client.get(
            f"/api/incidents/{incident['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert len(detail.json()["events"]) == 5
        assert client.get(
            "/api/audit/verify", headers={"Authorization": f"Bearer {token}"}
        ).json()["valid"] is True
        assert client.patch(
            f"/api/incidents/{incident['id']}",
            json={"status": "investigating"},
            headers={"Authorization": f"Bearer {token}"},
        ).status_code == 200


def test_viewer_cannot_ingest_events():
    application, client = build_client()
    with client:
        token = login(client)
        with application.state.session_factory() as session:
            session.add(
                User(
                    email="viewer@test.local",
                    password_hash=hash_password("viewer-password"),
                    role="viewer",
                )
            )
            session.commit()
        viewer_login = client.post(
            "/api/auth/login",
            json={"email": "viewer@test.local", "password": "viewer-password"},
        )
        assert viewer_login.status_code == 200
        response = client.post(
            "/api/events",
            json=[
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "gateway",
                    "host": "web-01",
                    "event_type": "normal",
                    "severity": "low",
                    "message": "request complete",
                }
            ],
            headers={"Authorization": f"Bearer {viewer_login.json()['access_token']}"},
        )
        assert response.status_code == 403


def test_audit_chain_detects_record_tampering():
    application, client = build_client()
    with client:
        token = login(client)
        with application.state.session_factory() as session:
            record = session.scalar(select(AuditRecord))
            assert record is not None
            record.action = "tampered.action"
            session.commit()
        response = client.get(
            "/api/audit/verify", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["valid"] is False

# Sentinel - Cybersecurity Intelligence and Threat Monitoring

Sentinel is a runnable defensive-security MVP for collecting application and
system events, detecting suspicious activity, prioritizing incidents, and
reviewing investigation timelines.

## Included

- FastAPI API with bearer-token authentication and viewer, analyst, and admin roles.
- Batch event ingestion with rules for suspicious logins, malware, privilege
  escalation, and repeated authentication failures.
- Incident risk scoring, status updates, event timelines, and dashboard metrics.
- Hash-chained audit records for authentication, ingestion, incident changes,
  and audit-chain verification.
- React + TypeScript dashboard with incident filtering and investigation details.
- PostgreSQL-backed Docker Compose setup and SQLite support for local development.

This MVP intentionally uses transparent rules rather than claiming ML-based
detection. OpenSearch, Redis-backed workers, production SSO, and model-generated
summaries are follow-on integrations, not prerequisites for running this slice.

## Run with Docker

1. Copy `.env.example` to `.env`, set `SECRET_KEY`,
   `BOOTSTRAP_ADMIN_PASSWORD`, and `POSTGRES_PASSWORD` to unique values, and
   update `DATABASE_URL` to match the PostgreSQL database, user, and password.
2. Run `docker compose up --build`.
3. Open <http://localhost:5173>.
4. Sign in with `admin@sentinel.local` and the password configured above.

The API is available at <http://localhost:8000>; interactive API documentation
is at <http://localhost:8000/docs>.

## Run locally

### API

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-development-secret"
$env:BOOTSTRAP_ADMIN_PASSWORD = "replace-this-development-password"
uvicorn app.main:app --reload
```

Without `DATABASE_URL`, the API creates `backend/sentinel.db` using SQLite.

### Web app

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Vite proxies `/api` calls to the API at `http://localhost:8000`.

## Ingest an event

Use an analyst or admin bearer token and send a JSON array to `POST /api/events`:

```json
[
  {
    "timestamp": "2026-10-15T05:30:00Z",
    "source": "web-gateway",
    "host": "web-01",
    "username": "jdoe",
    "event_type": "authentication_failure",
    "source_ip": "203.0.113.42",
    "severity": "medium",
    "message": "Invalid password"
  }
]
```

Five or more authentication failures for the same account and source IP within
ten minutes create a high-severity incident. `suspicious_login`,
`malware_detected`, and `privilege_escalation` events also create incidents.

## API overview

- `POST /api/auth/login` - exchange email/password for a bearer token.
- `GET /api/auth/me` - inspect the authenticated account and role.
- `GET /api/summary` - dashboard counts and recent events.
- `GET /api/incidents` - filter incidents by status, severity, and text.
- `GET /api/incidents/{id}` - incident details and chronological event timeline.
- `PATCH /api/incidents/{id}` - set status to `open`, `investigating`, or `resolved`.
- `POST /api/events` - ingest up to 500 events per request.
- `GET /api/audit` and `GET /api/audit/verify` - inspect and verify the audit chain.

Viewer accounts can read security data. Analysts can ingest events and update
incidents. Admins can do both and inspect the audit trail. The initial admin is
created from `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`; do not use
the development fallback password in a deployed environment.

## Tests

From `backend`, install the requirements and run:

```powershell
pytest
```

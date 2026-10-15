import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditRecord, User, utc_now

GENESIS_HASH = "0" * 64


def append_audit(
    session: Session,
    actor: User | str,
    action: str,
    entity_type: str,
    entity_id: str,
) -> AuditRecord:
    previous = session.scalar(select(AuditRecord).order_by(AuditRecord.id.desc()).limit(1))
    previous_hash = previous.record_hash if previous else GENESIS_HASH
    timestamp = utc_now()
    email = actor.email if isinstance(actor, User) else actor
    record_hash = calculate_hash(
        previous_hash, timestamp, email, action, entity_type, entity_id
    )
    record = AuditRecord(
        timestamp=timestamp,
        actor_email=email,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        previous_hash=previous_hash,
        record_hash=record_hash,
    )
    session.add(record)
    return record


def calculate_hash(
    previous_hash: str,
    timestamp: datetime,
    actor_email: str,
    action: str,
    entity_type: str,
    entity_id: str,
) -> str:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    payload = "\x1f".join(
        (
            previous_hash,
            timestamp.isoformat(),
            actor_email,
            action,
            entity_type,
            entity_id,
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_chain(records: list[AuditRecord]) -> bool:
    previous_hash = GENESIS_HASH
    for record in records:
        if record.previous_hash != previous_hash:
            return False
        expected = calculate_hash(
            previous_hash,
            record.timestamp,
            record.actor_email,
            record.action,
            record.entity_type,
            record.entity_id,
        )
        if record.record_hash != expected:
            return False
        previous_hash = record.record_hash
    return True

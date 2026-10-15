from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    id: int
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class EventIn(BaseModel):
    timestamp: datetime
    source: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=120)
    username: str = Field(default="", max_length=255)
    event_type: str = Field(min_length=1, max_length=80)
    source_ip: str = Field(default="", max_length=64)
    severity: Literal["low", "medium", "high", "critical"] = "low"
    message: str = Field(min_length=1, max_length=4000)


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    host: str
    username: str
    event_type: str
    source_ip: str
    severity: str
    message: str
    incident_id: int | None

    model_config = ConfigDict(from_attributes=True)


class IncidentOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    risk_score: int
    status: str
    rule_key: str
    created_at: datetime
    updated_at: datetime
    event_count: int


class IncidentDetail(IncidentOut):
    events: list[EventOut]


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"]


class AuditOut(BaseModel):
    id: int
    timestamp: datetime
    actor_email: str
    action: str
    entity_type: str
    entity_id: str
    record_hash: str

    model_config = ConfigDict(from_attributes=True)

import os

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def create_session_factory(database_url: str | None = None) -> tuple[Engine, sessionmaker[Session]]:
    url = database_url or os.getenv("DATABASE_URL", "sqlite:///./sentinel.db")
    options: dict[str, object] = {}
    if url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            options["poolclass"] = StaticPool
    engine = create_engine(url, **options)
    return engine, sessionmaker[Session](bind=engine, autoflush=False, expire_on_commit=False)

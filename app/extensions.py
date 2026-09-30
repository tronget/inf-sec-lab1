"""Flask extensions and the SQLAlchemy 2.x database handle.

Plain SQLAlchemy (no Flask-SQLAlchemy) is used deliberately: it keeps the
dependency surface small and makes the *parameterised query* story explicit.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool


class Database:
    """Small application-scoped wrapper around a SQLAlchemy engine/session."""

    def __init__(self) -> None:
        self.engine: Optional[Engine] = None
        self.session_factory: Optional[sessionmaker] = None
        self.session: Any = None

    def init_app(self, app: Flask) -> None:
        url = str(app.config["DATABASE_URL"])
        options: Dict[str, Any] = {
            "echo": bool(app.config.get("SQLALCHEMY_ECHO", False)),
            "future": True,
            "pool_pre_ping": True,
        }
        if url.startswith("sqlite"):
            # SQLite + Flask test client / threaded dev server.
            options["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url:
                # Keep one shared connection so the schema survives between
                # requests inside a single test.
                options["poolclass"] = StaticPool
                options.pop("pool_pre_ping", None)

        self.engine = create_engine(url, **options)
        if url.startswith("sqlite"):
            _enable_sqlite_foreign_keys(self.engine)

        self.session_factory = sessionmaker(
            bind=self.engine, autoflush=False, expire_on_commit=False, future=True
        )
        self.session = scoped_session(self.session_factory)

        app.extensions["database"] = self

        @app.teardown_appcontext
        def _remove_session(exception: Optional[BaseException]) -> None:
            if exception is not None:
                self.session.rollback()
            self.session.remove()

    def create_all(self) -> None:
        from app.models import Base

        if self.engine is None:  # pragma: no cover - defensive
            raise RuntimeError("Database.init_app() has not been called.")
        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        from app.models import Base

        if self.engine is None:  # pragma: no cover - defensive
            raise RuntimeError("Database.init_app() has not been called.")
        Base.metadata.drop_all(self.engine)

    @property
    def s(self) -> Session:
        """The current scoped session."""
        if self.session is None:  # pragma: no cover - defensive
            raise RuntimeError("Database.init_app() has not been called.")
        return self.session


def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    """SQLite ignores FK constraints unless the pragma is enabled per connection."""

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


db = Database()

#: Brute-force protection for the authentication endpoints.
limiter = Limiter(key_func=get_remote_address)

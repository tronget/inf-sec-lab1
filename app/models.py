"""SQLAlchemy 2.x ORM models.

Using the ORM (rather than string-built SQL) is the primary control against
SQL injection: every value below is transported to the database as a bound
parameter, never as part of the statement text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp (``datetime.utcnow`` is deprecated)."""
    return datetime.now(timezone.utc)


def to_utc_iso(value: datetime) -> str:
    """Render a timestamp as an ISO-8601 string that always carries an offset.

    SQLite has no native timezone type, so values read back from the database
    are naive. They are stored in UTC, so the offset is re-attached here to keep
    the API's timestamp format identical on every route.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class Base(DeclarativeBase):
    """Declarative base for all models."""


class User(Base):
    """An API account. Only the bcrypt *hash* of the password is ever stored."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    notes: Mapped[List[Note]] = relationship(
        back_populates="owner", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        # Never render the password hash.
        return f"<User id={self.id} username={self.username!r}>"


class Note(Base):
    """A note owned by exactly one user (used by ``/api/data``)."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    owner: Mapped[User] = relationship(back_populates="notes")

    __table_args__ = (Index("ix_notes_owner_created", "owner_id", "created_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Note id={self.id} owner_id={self.owner_id}>"


class RevokedToken(Base):
    """Denylist of revoked JWT ids (``jti``) - powers ``POST /auth/logout``."""

    __tablename__ = "revoked_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    token_type: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RevokedToken jti={self.jti!r}>"

"""Flask CLI commands for local operation."""

from __future__ import annotations

import click
from flask import Flask
from sqlalchemy import select

from app.extensions import db
from app.models import Note, User
from app.security.passwords import hash_password, validate_password_policy
from app.security.tokens import purge_expired_tokens

#: Credential used by the development-only ``seed-db`` command. It is not a
#: secret: it is printed to stdout and the command is never run in production.
DEMO_ACCOUNT_CREDENTIAL = "Lab1-Demo-Pass!2026"


def register_cli(app: Flask) -> None:
    """Attach the custom commands to ``app``."""

    @app.cli.command("init-db")
    def init_db() -> None:
        """Create all database tables."""
        db.create_all()
        click.echo("Database schema created.")

    @app.cli.command("seed-db")
    def seed_db() -> None:
        """Insert two demo users with a couple of notes each."""
        created = 0
        rounds = int(app.config["BCRYPT_ROUNDS"])
        for username in ("alice", "bob"):
            existing = db.s.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if existing is not None:
                continue
            user = User(
                username=username, password_hash=hash_password(DEMO_ACCOUNT_CREDENTIAL, rounds)
            )
            db.s.add(user)
            db.s.flush()
            db.s.add(
                Note(
                    owner_id=user.id,
                    title=f"Welcome, {username}",
                    content="Your first note. Only you can read it.",
                )
            )
            created += 1
        db.s.commit()
        click.echo(f"Seeded {created} user(s). Demo password: {DEMO_ACCOUNT_CREDENTIAL}")

    @app.cli.command("create-user")
    @click.option("--username", required=True, help="Account name (3-32 chars).")
    @click.password_option(
        "--password",
        required=True,
        prompt=True,
        confirmation_prompt=True,
        help="Password (prompted, never echoed).",
    )
    def create_user(username: str, password: str) -> None:
        """Create a single account from the command line."""
        problems = validate_password_policy(password)
        if problems:
            raise click.ClickException("Password " + "; ".join(problems) + ".")
        existing = db.s.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if existing is not None:
            raise click.ClickException("Username is already taken.")
        rounds = int(app.config["BCRYPT_ROUNDS"])
        db.s.add(User(username=username, password_hash=hash_password(password, rounds)))
        db.s.commit()
        click.echo(f"Created user {username}.")

    @app.cli.command("purge-tokens")
    def purge_tokens() -> None:
        """Drop denylist entries for tokens that have expired anyway."""
        removed = purge_expired_tokens()
        click.echo(f"Removed {removed} expired denylist entries.")

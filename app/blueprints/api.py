"""Protected business endpoints (``/api/*``).

Every route here is guarded by ``@jwt_required()`` and every database access
goes through SQLAlchemy bound parameters. Ownership is verified explicitly on
single-resource routes (OWASP A01:2021 - Broken Access Control / IDOR).
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy import func, select, text

from app.errors import ApiError
from app.extensions import db
from app.models import Note, to_utc_iso
from app.schemas import DataQuery, NoteCreateRequest
from app.security.decorators import current_user, jwt_required
from app.security.sanitize import escape_like, sanitize_text

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _serialize_note(note: Note) -> Dict[str, Any]:
    """Render a note for the API.

    ``title`` and ``content`` are attacker-controlled, so they are HTML-escaped
    on the way out: a stored ``<script>`` becomes ``&lt;script&gt;`` and cannot
    execute even if a front-end injects it with ``innerHTML``.
    """
    return {
        "id": note.id,
        "owner_id": note.owner_id,
        "title": sanitize_text(note.title),
        "content": sanitize_text(note.content),
        "created_at": to_utc_iso(note.created_at),
        "updated_at": to_utc_iso(note.updated_at),
    }


@api_bp.get("/me")
@jwt_required()
def me() -> Tuple[Response, int]:
    """Profile of the authenticated user."""
    user = current_user()
    return (
        jsonify(
            {
                "id": user.id,
                "username": sanitize_text(user.username),
                "is_active": user.is_active,
                "created_at": to_utc_iso(user.created_at),
            }
        ),
        200,
    )


@api_bp.get("/data")
@jwt_required()
def list_data() -> Tuple[Response, int]:
    """List the caller's notes with pagination and an optional ``?q=`` search.

    SQLi protection: ``q`` is bound as a parameter by SQLAlchemy - it is never
    concatenated into the statement. ``escape_like`` additionally neutralises
    the ``%`` and ``_`` wildcards so the pattern keeps its intended meaning.
    """
    query = DataQuery.model_validate(request.args.to_dict(flat=True))
    user = current_user()

    conditions = [Note.owner_id == user.id]
    if query.q:
        pattern = "%" + escape_like(query.q) + "%"
        conditions.append(Note.title.ilike(pattern, escape="\\"))

    total = db.s.execute(select(func.count()).select_from(Note).where(*conditions)).scalar_one()

    stmt = (
        select(Note)
        .where(*conditions)
        .order_by(Note.created_at.desc(), Note.id.desc())
        .limit(query.per_page)
        .offset((query.page - 1) * query.per_page)
    )
    notes = list(db.s.execute(stmt).scalars())

    return (
        jsonify(
            {
                "items": [_serialize_note(note) for note in notes],
                "page": query.page,
                "per_page": query.per_page,
                "total": total,
                "query": sanitize_text(query.q) if query.q else None,
            }
        ),
        200,
    )


@api_bp.post("/data")
@jwt_required()
def create_data() -> Tuple[Response, int]:
    """Create a note owned by the caller (the assignment's third endpoint)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError(400, "bad_request", "Request body must be a JSON object.")

    payload = NoteCreateRequest.model_validate(body)
    user = current_user()

    note = Note(owner_id=user.id, title=payload.title, content=payload.content)
    db.s.add(note)
    db.s.commit()

    current_app.logger.info(
        "data.note.created",
        extra={"event": "data.note.created", "user_id": user.id, "note_id": note.id},
    )
    return jsonify(_serialize_note(note)), 201


@api_bp.get("/data/<int:note_id>")
@jwt_required()
def get_data(note_id: int) -> Tuple[Response, int]:
    """Fetch one note, enforcing ownership.

    This route intentionally uses a raw ``text()`` statement to demonstrate a
    *prepared statement*: the values travel as the named bind parameters
    ``:note_id`` / ``:owner_id``. String concatenation or f-strings are never
    used to build SQL anywhere in this project.
    """
    user = current_user()
    stmt = text(
        "SELECT id, owner_id, title, content, created_at, updated_at FROM notes WHERE id = :note_id"
    )
    row = db.s.execute(stmt, {"note_id": note_id}).mappings().first()
    if row is None:
        raise ApiError(404, "not_found", "Note not found.")

    if int(row["owner_id"]) != user.id:
        current_app.logger.warning(
            "authz.denied",
            extra={
                "event": "authz.denied",
                "user_id": user.id,
                "note_id": note_id,
                "reason": "not_owner",
            },
        )
        raise ApiError(403, "forbidden", "You do not have access to this resource.")

    note = db.s.get(Note, note_id)
    return jsonify(_serialize_note(note)), 200


@api_bp.delete("/data/<int:note_id>")
@jwt_required()
def delete_data(note_id: int) -> Tuple[str, int]:
    """Delete one of the caller's own notes."""
    user = current_user()
    note = db.s.get(Note, note_id)
    if note is None:
        raise ApiError(404, "not_found", "Note not found.")
    if note.owner_id != user.id:
        current_app.logger.warning(
            "authz.denied",
            extra={
                "event": "authz.denied",
                "user_id": user.id,
                "note_id": note_id,
                "reason": "not_owner",
            },
        )
        raise ApiError(403, "forbidden", "You do not have access to this resource.")

    db.s.delete(note)
    db.s.commit()
    current_app.logger.info(
        "data.note.deleted",
        extra={"event": "data.note.deleted", "user_id": user.id, "note_id": note_id},
    )
    return "", 204

from __future__ import annotations
import secrets
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User
from app.models.web_session import WebSession

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def get_client_info(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua

def create_web_session(
        db: Session,
        request: Request,
        user_id: int,
) -> WebSession:
    session_id = secrets.token_urlsafe(32)
    ip, ua = get_client_info(request)

    ws = WebSession(
        session_id=session_id,
        user_id=user_id,
        ip=ip,
        user_agent=ua,
    )
    db.add(ws)
    db.commit()
    db.refresh(ws)

    request.session["session_id"] = session_id

    return ws

def get_web_session(
        db: Session,
        request: Request,
) -> WebSession | None:
    session_id = request.session.get("session_id")
    if not session_id:
        return None

    ws = db.execute(
        select(WebSession).where(WebSession.session_id == session_id)
    ).scalar_one_or_none()

    if ws is None:
        request.session.pop("session_id", None)
        return None

    if ws.revoked_at is not None:
        request.session.pop("session_id", None)
        return None

    ws.last_seen_at = _utcnow()
    db.commit()
    
    return ws

def get_web_user(
        db: Session,
        request: Request,
) -> User | None:
    ws = get_web_session(db, request)
    if ws is None:
        return None

    user = db.execute(
        select(User).where(User.id == ws.user_id)
    ).scalar_one_or_none()

    if user is None or not user.is_active:
        request.session.pop("session_id", None)
        return None

    return User

def destroy_web_session(db: Session, request: Request) -> None:
    session_id = request.session.get("session_id")
    if session_id:
        ws = db.execute(
            select(WebSession).where(WebSession.session_id == session_id)
        ).scalar_one_or_none()
        if ws is not None:
            ws.revoked_at = _utcnow()
            db.commit()

    request.session.pop("session_id", None)
    request.session.pop("csrf_token", None)
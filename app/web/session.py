from __future__ import annotations
import secrets
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.web_session import WebSession

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def get_client_info(request: Request) -> tuple[str | None, str | None]:
    """Извлекает IP-адрес и User-Agent HTTP-клиента из запроса.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: tuple[str | None, str | None]).
    """
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua

def create_web_session(
        db: Session,
        request: Request,
        user_id: int,
) -> WebSession:
    """Создаёт веб-сессию пользователя и сохраняет её в базе данных.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        user_id (int): идентификатор пользователя в базе данных.

    Возвращает:
        Результат выполнения операции (тип: WebSession).
    """
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
    """Находит веб-сессию и проверяет срок её действия.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: WebSession | None).
    """
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
    """Загружает активного пользователя, связанного с веб-сессией.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: User | None).
    """
    ws = get_web_session(db, request)
    if ws is None:
        return None

    user = db.execute(
        select(User).where(User.id == ws.user_id)
    ).scalar_one_or_none()

    if user is None or not user.is_active:
        request.session.pop("session_id", None)
        return None

    return user

def destroy_web_session(db: Session, request: Request) -> None:
    """Удаляет веб-сессию из базы данных.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        None (значение не возвращается).
    """
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
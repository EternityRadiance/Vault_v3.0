from __future__ import annotations
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.models.oauth_client import OAuthClient
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession
from app.oauth.errors import INVALID_GRANT, INVALID_SCOPE, oauth_json_error
from app.oauth.tokens import (
    generate_refresh_token,
    issue_token_response,
    sha256_hex,
)

def _utcnow() -> timezone:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: timezone).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def handle_refresh_token_grant(
        db: Session,
        request: Request,
        *,
        client: OAuthClient,
        refresh_token: str | None,
        scope: str | None,
) -> dict:
    """Проверяет и ротирует refresh token, обрабатывая повторное использование.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        client (OAuthClient): OAuth-клиент, для которого выполняется операция.
        refresh_token (str | None): значение refresh token из запроса.
        scope (str | None): строка запрошенных OAuth-разрешений.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    if not refresh_token:
        oauth_json_error(INVALID_GRANT, "refresh_token is required")

    token_hash = sha256_hex(refresh_token)
    rt = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    info = get_client_info(request)

    if rt is None:
        write_event(
            db,
            OAuthEvents.TOKEN_REUSE_DETECTED,
            actor_id=None,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "grant_type": "refresh_token", "reason": "unknown_token"
            },
        )
        oauth_json_error(INVALID_GRANT, "Invalid refresh_token")

    if rt.client_id != client.client_id:
        oauth_json_error(INVALID_GRANT, "refresh_token issued to a different client")

    if rt.used_at is not None:
        _revoke_family(
            db,
            family_id=rt.family_id,
            reason="refresh_token_reuse",
            ip=info["ip"],
            user_agent=info["user_agent"],
            actor_id=rt.user_id,
            client_id=client.client_id,
        )
        oauth_json_error(INVALID_GRANT, "refresh_token has already been used")

    if rt.revoked_at is not None:
        oauth_json_error(INVALID_GRANT, "refresh_token has been revoked")

    if rt.expires_at < _utcnow():
        oauth_json_error(INVALID_GRANT, "refresh_token has expired")

    original_scopes = rt.scope.split() if rt.scope else [] 
    if scope:
        requested = scope.split()
        if not set(requested).issubset(set(original_scopes)):
            oauth_json_error(INVALID_SCOPE, "Requested scope exceeds original")
        new_scopes = requested
    else:
        new_scopes = original_scopes

    rt.used_at = _utcnow()

    raw_new_refresh, new_rt = generate_refresh_token(
        db,
        user_id=rt.user_id,
        client_id=rt.client_id,
        scope=" ".join(new_scopes),
        family_id=rt.family_id,
    )
    rt.replaced_by_hash = new_rt.token_hash

    session = db.execute(
        select(UserSession).where(UserSession.family_id == rt.family_id)
    ).scalar_one_or_none()
    if session is not None:
        session.last_seen_at = _utcnow()

    db.commit()

    user = db.execute(select(User).where(User.id == rt.user_id)).scalar_one_or_none()
    if user is None or not user.is_active:
        oauth_json_error(INVALID_GRANT, "User not found or inactive")

    write_event(
        db,
        OAuthEvents.TOKEN_REFRESHED,
        actor_id=user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "grant_type": "refresh_token",
            "scope": " ".join(new_scopes),
            "family_id": rt.family_id,
        },
    )

    return issue_token_response(
        user=user,
        client_id=client.client_id,
        scopes=new_scopes,
        raw_refresh=raw_new_refresh,
        include_id_token=True,
    )


def _revoke_family(
    db: Session,
    *,
    family_id: str,
    reason: str,
    ip: str | None,
    user_agent: str | None,
    actor_id: int | None,
    client_id: str,
) -> None:
    """Отзывает все refresh-токены указанного семейства и записывает событие аудита.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        family_id (str): идентификатор семейства refresh-токенов.
        reason (str): причина выполняемой операции или отзыва.
        ip (str | None): IP-адрес клиента.
        user_agent (str | None): значение заголовка User-Agent клиента.
        actor_id (int | None): идентификатор пользователя, выполнившего действие.
        client_id (str): идентификатор OAuth-клиента.

    Возвращает:
        None (значение не возвращается).
    """
    now = _utcnow()
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.execute(
        update(UserSession)
        .where(UserSession.family_id == family_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.commit()

    write_event(
        db,
        OAuthEvents.TOKEN_REUSE_DETECTED,
        actor_id=actor_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        metadata={"family_id": family_id, "reason": reason},
    )
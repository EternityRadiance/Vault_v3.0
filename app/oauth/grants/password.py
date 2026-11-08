from __future__ import annotations
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.core.passwords import verify_password
from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.oauth.errors import (
    INVALID_GRANT,
    INVALID_SCOPE,
    UNAUTHORIZED_CLIENT,
    oauth_json_error,
)
from app.oauth.tokens import generate_refresh_token, issue_token_response

def handle_password_grant(
        db: Session, 
        request: Request,
        *,
        client: OAuthClient,
        username: str | None,
        password: str | None,
        scope: str | None,
) -> dict:
    """Проверяет учетные данные пользователя и выдает токены в рамках password grant.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        client (OAuthClient): OAuth-клиент, для которого выполняется операция.
        username (str | None): имя пользователя для аутентификации.
        password (str | None): пароль пользователя.
        scope (str | None): строка запрошенных OAuth-разрешений.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    if not username or not password:
        oauth_json_error(INVALID_GRANT, "username and password are required")

    if "password" not in (client.grant_types or []):
        oauth_json_error(UNAUTHORIZED_CLIENT, "password grant not allowed")

    user = db.execute(
        select(User).where(User.email == username.strip().lower())
    ).scalar_one_or_none()

    info = get_client_info(request)

    if user is None or not verify_password(password, user.hashed_password):
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=None,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "grant_type": "password",
                "username": username,
                "reason": "invalid_credentials",
            },
        )
        oauth_json_error(INVALID_GRANT, "Invalid username or password")

    if not user.is_active:
        oauth_json_error(INVALID_GRANT, "User is inactive")

    requested = scope.split() if scope else client.scopes or []
    if not set(requested).issubset(set(client.scopes or [])):
        oauth_json_error(INVALID_SCOPE, f"Allowed scopes: {sorted(client.scopes or [])}")

    raw_refresh, _ = generate_refresh_token(
        db,
        user_id=user.id,
        client_id=client.client_id,
        scope=" ".join(requested),
    )
    db.commit()

    write_event(
        db,
        OAuthEvents.TOKEN_ISSUED,
        actor_id=user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={"grant_type": "password", "scope": " ".join(requested)},
    )
    return issue_token_response(
        user=user,
        client_id=client.client_id,
        scopes=requested,
        raw_refresh=raw_refresh,
        include_id_token=True,
    )
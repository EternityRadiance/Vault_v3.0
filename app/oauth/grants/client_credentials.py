from __future__ import annotations
from fastapi import Request
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.config import settings
from app.core.security.jwt_rsa import sign_access_token
from app.models.oauth_client import OAuthClient
from app.oauth.errors import INVALID_SCOPE, UNAUTHORIZED_CLIENT, oauth_json_error

def handle_client_credentials_grant(
        db: Session,
        request: Request,
        *,
        client: OAuthClient,
        scope: str | None,
) -> dict:
    """Проверяет запрошенные scope и выдает токен для OAuth-клиента.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        client (OAuthClient): OAuth-клиент, для которого выполняется операция.
        scope (str | None): строка запрошенных OAuth-разрешений.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    if not client.is_confidential:
        oauth_json_error(
            UNAUTHORIZED_CLIENT,
            "client_credentials grant requires a confidential client",
        )

    if "client_credentials" not in (client.grant_types or []):
        oauth_json_error(UNAUTHORIZED_CLIENT, "client_credentials grant not allowed")

    requested = scope.split() if scope else client.scopes or []
    if not set(requested).issubset(set(client.scopes or [])):
        oauth_json_error(INVALID_SCOPE, f"Allowed scopes: {sorted(client.scopes or [])}")

    info = get_client_info(request)

    access = sign_access_token(
        sub=client.client_id,
        client_id=client.client_id,
        scopes=requested,
    )

    write_event(
        db,
        OAuthEvents.TOKEN_ISSUED,
        actor_id=None,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "grant_type": "client_credentials",
            "scope": " ".join(requested),
        },
    )

    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_sec,
        "scope": " ".join(requested),
    }

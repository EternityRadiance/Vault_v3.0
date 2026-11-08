from __future__ import annotations
import base64
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.passwords import verify_password
from app.models.oauth_client import OAuthClient
from app.oauth.errors import INVALID_CLIENT, oauth_json_error

def authenticate_client(
        db: Session,
        request: Request,
        client_id: str | None,
        client_secret: str | None,
) -> OAuthClient:
    """Аутентифицирует OAuth-клиента по переданным учетным данным.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        client_id (str | None): идентификатор OAuth-клиента.
        client_secret (str | None): секрет OAuth-клиента.

    Возвращает:
        Результат выполнения операции (тип: OAuthClient).
    """
    if not client_id or not client_secret:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                basic_id, basic_secret = decoded.split(":", 1)
                client_id = client_id or basic_id
                client_secret = client_secret or basic_secret
            except (ValueError, UnicodeDecodeError):
                oauth_json_error(INVALID_CLIENT, "Malformed Basic auth")

    if not client_id:
        oauth_json_error(INVALID_CLIENT, "client_id is required")

    client = db.execute(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    ).scalar_one_or_none()

    if client is None or not client.is_active:
        oauth_json_error(INVALID_CLIENT, "Unknown or inactive client")

    if not client.is_confidential:
        return client

    if not client_secret:
        oauth_json_error(INVALID_CLIENT, "client_secret is required")

    if not client.hashed_secret or not verify_password(client_secret, client.hashed_secret):
        oauth_json_error(INVALID_CLIENT, "Invalid client_secret")

    return client
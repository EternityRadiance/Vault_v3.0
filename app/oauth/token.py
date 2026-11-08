from __future__ import annotations
from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.oauth.client_auth import authenticate_client
from app.oauth.errors import UNSUPPORTED_GRANT_TYPE, oauth_json_error
from app.oauth.grants.authorization_code import handle_authorization_code_grant
from app.oauth.grants.client_credentials import handle_client_credentials_grant
from app.oauth.grants.password import handle_password_grant
from app.oauth.grants.refresh_token import handle_refresh_token_grant

router = APIRouter(tags=["oauth"])

@router.post("/oauth/token")
def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    scope: str | None = Form(default=None),
    username: str | None = Form(default=None),
    password: str | None = Form(default=None),
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    refresh_token_value: str | None = Form(default=None, alias="refresh_token"),
    db: Session = Depends(get_db),
) -> dict:
    """Обрабатывает запрос выдачи токена и вызывает обработчик указанного grant type.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        grant_type (str): тип OAuth grant из запроса.
        client_id (str | None): идентификатор OAuth-клиента.
        client_secret (str | None): секрет OAuth-клиента.
        scope (str | None): строка запрошенных OAuth-разрешений.
        username (str | None): имя пользователя для аутентификации.
        password (str | None): пароль пользователя.
        code (str | None): authorization code для обмена.
        redirect_uri (str | None): адрес возврата OAuth-клиента.
        code_verifier (str | None): PKCE code verifier, полученный от клиента.
        refresh_token_value (str | None): значение refresh token из запроса.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    client = authenticate_client(db, request, client_id, client_secret)

    if grant_type == "password":
        return handle_password_grant(
            db, request,
            client=client,
            username=username,
            password=password,
            scope=scope,
        )

    if grant_type == "authorization_code":
        return handle_authorization_code_grant(
            db, request,
            client=client,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    if grant_type == "refresh_token":
        return handle_refresh_token_grant(
            db, request,
            client=client,
            refresh_token=refresh_token_value,
            scope=scope,
        )

    if grant_type == "client_credentials":
        return handle_client_credentials_grant(
            db, request,
            client=client,
            scope=scope,
        )

    oauth_json_error(
        UNSUPPORTED_GRANT_TYPE,
        f"grant_type={grant_type!r} is not supported",
    )
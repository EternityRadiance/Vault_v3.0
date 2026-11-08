from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Form, Request
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security.jwt_rsa import load_public_key
from app.db.session import get_db
from app.models.refresh_token import RefreshToken
from app.oauth.client_auth import authenticate_client
from app.oauth.tokens import sha256_hex
from app.redis_client import is_blacklisted

router = APIRouter(tags=["oauth"])

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

@router.post("/oauth/introspect")
def introspect(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    db: Session = Depends(get_db),
) -> dict:
    """Аутентифицирует OAuth-клиента и возвращает сведения о действительности токена.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        token (str): исходное значение токена.
        token_type_hint (str | None): подсказка о типе токена из запроса.
        client_id (str | None): идентификатор OAuth-клиента.
        client_secret (str | None): секрет OAuth-клиента.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    client = authenticate_client(db, request, client_id, client_secret)

    if not client.is_confidential:
        return {"active": False}

    if token_type_hint == "refresh_token" or not token_type_hint:
        result = _introspect_refresh(db, token)
        if result is not None:
            return result

    if token_type_hint == "access_token" or not token_type_hint:
        result = _introspect_access(token)
        if result is not None:
            return result
    return {"active": False}

def _introspect_access(token: str) -> dict | None:
    """Проверяет access token и формирует поля introspection-ответа.

    Параметры:
        token (str): исходное значение токена.

    Возвращает:
        Результат выполнения операции (тип: dict | None).
    """
    try:
        payload = jwt.decode(
            token,
            load_public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
    except JWTError:
        return None

    jti = payload.get("jti")
    if not jti:
        return None

    if is_blacklisted(jti): 
        return {"active": False}

    aud = payload.get("aud")
    return {
        "active": True,
        "sub": payload.get("sub"),
        "scope": payload.get("scope", ""),
        "client_id": aud if isinstance(aud, str) else None,
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "iss": payload.get("iss"),
        "token_type": "access_token",
    }

def _introspect_refresh(db: Session, raw_token: str) -> dict | None:
    """Находит refresh token и формирует поля introspection-ответа.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        raw_token (str): исходное значение токена до хеширования.

    Возвращает:
        Результат выполнения операции (тип: dict | None).
    """
    token_hash = sha256_hex(raw_token)
    rt = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if rt is None:
        return None

    now = _utcnow()
    if rt.revoked_at is not None or rt.used_at is not None or rt.expires_at < now:
        return {"active": False}

    exp_ts = int(rt.expires_at.replace(tzinfo=timezone.utc).timestamp())

    return {
        "active": True,
        "sub": str(rt.user_id),
        "client_id": rt.client_id,
        "scope": rt.scope,
        "exp": exp_ts,
        "token_type": "refresh_token",
    }
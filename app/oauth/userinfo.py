from __future__ import annotations
from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security.jwt_rsa import load_public_key
from app.db.session import get_db
from app.models.user import User
from app.redis_client import is_blacklisted

router = APIRouter(tags=["oauth"])

@router.get("/oauth/userinfo", include_in_schema=False)
def userinfo(request: Request, db: Session = Depends(get_db)) -> dict:
    """Проверяет access token и возвращает разрешённые атрибуты пользователя.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth[7:].strip()

    try:
        payload = jwt.decode(
            token,
            load_public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW_Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has no sub",
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not associated with a user",
        )

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    scopes = (payload.get("scope") or "").split()

    result: dict = {"sub": str(user.id)}

    if "email" in scopes:
        result["email"] = user.email
        result["email_verified"] = True

    if "profile" in scopes:
        local = user.email.split("@")[0]
        result["preferred_username"] = local
        result["name"] = local
        result["updated_at"] = int(user.created_at.replace(tzinfo=timezone.utc).timestamp())

    return result
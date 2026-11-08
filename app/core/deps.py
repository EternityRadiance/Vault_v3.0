from __future__ import annotations
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.jwt import decode_token
from app.db.session import get_db
from app.models.user import User
from app.redis_client import is_blacklisted


bearer_scheme = HTTPBearer(auto_error=False)


def _extract_bearer_token(request: Request) -> str | None:
    """Извлекает Bearer-токен только из заголовка Authorization и не использует cookie веб-сессии.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: str | None).
    """
    auth = request.headers.get("Authorization")
    if auth:
        parts = auth.split(maxsplit=1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip() or None
    return None


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Проверяет токен аутентификации и загружает соответствующего активного пользователя.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        credentials (HTTPAuthorizationCredentials | None): учетные данные Bearer, полученные от FastAPI security-зависимости..
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    token = credentials.credentials if credentials else None
    if not token:
        token = _extract_bearer_token(request)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            cookie_csrf = request.cookies.get("vault_csrf")
            header_csrf = request.headers.get("X-CSRF-Token")
            if not cookie_csrf or not header_csrf or cookie_csrf != header_csrf:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token missing or invalid",
                )

    jti = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is disabled.",
        )

    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Проверяет наличие у текущего пользователя прав администратора.

    Параметры:
        user (User): пользователь, данные или права которого обрабатываются.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin only.",
        )
    return user
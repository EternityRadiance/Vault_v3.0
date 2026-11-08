from __future__ import annotations

from app.core.deps import _extract_bearer_token
from app.core.jwt import decode_token
from app.db import session as db_session_module
from app.models.user import User
from app.redis_client import is_blacklisted


def get_context_value(request, data) -> dict:
    """Формирует контекст GraphQL-запроса из HTTP-запроса и данных выполнения.

    Параметры:
        request: HTTP-запрос, переданный веб-фреймворком.
        data: данные выполнения GraphQL-запроса.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    db = db_session_module.SessionLocal()
    context = {"request": request, "db": db, "user": None}

    token = _extract_bearer_token(request)
    if token:
        try:
            payload = decode_token(token)
            jti = payload.get("jti")
            if jti and is_blacklisted(jti):
                raise ValueError("revoked")
            user_id = int(payload["sub"])
            user = db.get(User, user_id)
            if user is not None and user.is_active:
                context["user"] = user
        except (ValueError, KeyError, TypeError):
            pass

    return context
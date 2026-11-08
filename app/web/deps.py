from __future__ import annotations
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.web.session import get_web_user

def current_web_user(
        request: Request,
        db: Session = Depends(get_db),
) -> User | None:
    """Загружает пользователя, связанного с текущей веб-сессией.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: User | None).
    """
    return get_web_user(db, request)

def require_web_user(
        request: Request,
        db: Session = Depends(get_db),
) -> User:
    """Требует аутентифицированного пользователя веб-сессии.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    user = get_web_user(db, request)
    if user is None:
        next_url = request.url.path
        if request.url.query:
            next_url += "?" + request.url.query

        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail=f"/web/login?next={next_url}",
            headers={"Location": f"/web/login?next={next_url}"},
        )
    return user

def require_admin_web(
        request: Request,
        db: Session = Depends(get_db),
) -> User:
    """Требует пользователя веб-сессии с правами администратора.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    user = require_web_user(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user
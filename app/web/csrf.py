from __future__ import annotations
import secrets
from fastapi import HTTPException, Request, status

def generate_csrf_token() -> str:
    """Генерирует случайный CSRF-токен.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    return secrets.token_urlsafe(32)

def get_csrf_token(request: Request) -> str:
    """Получает CSRF-токен для запроса или создаёт новый.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    token = request.session.get("csrf_token")
    if not token:
        token = generate_csrf_token()
        request.session["csrf_token"] = token
    return token

def verify_csrf(request: Request, form_token: str | None) -> None:
    """Сравнивает CSRF-токены из cookie и заголовка запроса.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        form_token (str | None): CSRF-токен, переданный в поле формы..

    Возвращает:
        None (значение не возвращается).
    """
    if not form_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    session_token = request.session.get("csrf_token")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing in session")

    if not secrets.compare_digest(session_token, form_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
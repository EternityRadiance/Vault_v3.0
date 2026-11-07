from __future__ import annotations
import secrets
from fastapi import HTTPException, Request, status

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = generate_csrf_token()
        request.session["csrf_token"] = token
    return token

def verify_csrf(request: Request, form_token: str | None) -> None:
    if not form_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    session_token = request.session.get("csrf_token")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing in session")

    if not secrets.compare_digest(session_token, form_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
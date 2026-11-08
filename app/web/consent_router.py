from __future__ import annotations
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.config import settings
from app.db.session import get_db
from app.models.auth_code import AuthCode
from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.oauth.scope_descriptions import describe_scope
from app.redis_client import get_redis
from app.web.context import render
from app.web.csrf import verify_csrf
from app.web.deps import require_web_user

router = APIRouter(tags=["web-oauth"])

CONSENT_KEY_PREFIX = "consent:"

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _sha256_hex(value: str) -> str:
    """Вычисляет SHA-256-хеш строки в шестнадцатеричном виде.

    Параметры:
        value (str): значение для обработки.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def _load_pending(request_id: str, user: User) -> dict | None:
    """Загружает и проверяет ожидающий запрос согласия пользователя.

    Параметры:
        request_id (str): идентификатор ожидающего OAuth-запроса согласия..
        user (User): пользователь, данные или права которого обрабатываются.

    Возвращает:
        Результат выполнения операции (тип: dict | None).
    """
    raw = get_redis().get(f"{CONSENT_KEY_PREFIX}{request_id}")
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("user_id") != user.id:
        return None
    return data

@router.get("/consent")
def consent_page(
    request: Request, 
    request_id: str = Query(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user)
):
    """Формирует страницу подтверждения запрошенных OAuth-разрешений.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        request_id (str): идентификатор ожидающего OAuth-запроса, для которого показывается согласие..
        db (Session): сессия базы данных для чтения и сохранения данных.
        user (User): пользователь, данные или права которого обрабатываются.

    Возвращает:
        Результат выполнения операции (тип: TemplateResponse).
    """
    data = _load_pending(request_id, user)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Согласие истекло или недоступно",
        )

    client = db.execute(
        select(OAuthClient).where(OAuthClient.client_id == data["client_id"])
    ).scalar_one_or_none()

    if client is None or not client.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Клиент не найден или выключен",
        )

    scopes = data.get("scope", "").split() if data.get("scope") else []
    scope_details = [describe_scope(s) for s in scopes]

    return render(
        request,
        "oauth/consent.html",
        current_user=user,
        request_id=request_id,
        client=client,
        scopes=scopes,
        scope_details=scope_details,
        redirect_uri=data.get("redirect_uri", ""),
    )

@router.post("/consent")
async def consent_submit(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    """Обрабатывает решение пользователя по OAuth-согласию и перенаправляет клиента.

    Параметры:
        request (Request): HTTP-запрос, переданный веб-фреймворком.
        db (Session): сессия базы данных для чтения и сохранения данных.
        user (User): пользователь, данные или права которого обрабатываются.

    Возвращает:
        Результат выполнения операции (тип: RedirectResponse).
    """
    form = await request.form()
    verify_csrf(request, form.get("csrf_token"))

    request_id = form.get("request_id", "")
    decision = form.get("decision", "")

    if not request_id or decision not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный запрос",
        )

    data = _load_pending(request_id, user)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Согласие истекло или уже обработано",
        )

    get_redis().delete(f"{CONSENT_KEY_PREFIX}{request_id}")

    redirect_uri = data["redirect_uri"]
    state = data.get("state")
    info = get_client_info(request)
    client_id = data["client_id"]

    if decision == "deny":
        write_event(
            db,
            OAuthEvents.CONSENT_DENIED,
            actor_id=user.id,
            client_id=client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"scope": data.get("scope", "")},
        )
        params = {"error": "access_denied"}
        if state:
            params["state"] = state
        return RedirectResponse(
            f"{redirect_uri}?{urlencode(params)}",
            status_code=302,
        )

    raw_code = secrets.token_urlsafe(48)
    code_hash = _sha256_hex(raw_code)

    db.add(
        AuthCode(
            code_hash=code_hash,
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=data.get("scope", ""),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method"),
            nonce=data.get("nonce"),
            expires_at=_utcnow() + timedelta(seconds=settings.auth_code_ttl_sec),
        )
    )
    db.commit()

    write_event(
        db,
        OAuthEvents.CONSENT_GRANTED,
        actor_id=user.id,
        client_id=client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "scope": data.get("scope", ""),
            "redirect_uri": redirect_uri,
        },
    )

    params = {"code": raw_code}
    if state:
        params["state"] = state
    return RedirectResponse(
        f"{redirect_uri}?{urlencode(params)}",
        status_code=302,
    )
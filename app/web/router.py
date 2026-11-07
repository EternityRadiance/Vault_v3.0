from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents, UserEvents
from app.audit.service import get_client_info, write_event
from app.auth.service import (
    EmailAlreadyExistsError,
    register_user,
    authenticate_user,
    InvalidCredentialsError,
)
from app.core.passwords import WeakPasswordError, verify_password, hash_password, validate_policy
from app.db.session import get_db
from app.models.web_session import WebSession
from app.models.user import User
from app.web.context import render
from app.web.csrf import verify_csrf
from app.web.deps import require_web_user
from app.web.flash import flash
from app.web.forms import LoginForm, RegisterForm, parse_form
from app.web.session import create_web_session, destroy_web_session, get_web_user

router = APIRouter(prefix="/web", tags=["web"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@router.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    user = get_web_user(db, request)
    if user is None:
        return RedirectResponse("/web/login", status_code=303)
    return RedirectResponse("/web/account", status_code=303)


@router.get("/login")
def login_page(request: Request, next: str | None = None):
    return render(
        request,
        "auth/login.html",
        next=next or "",
    )


@router.post("/login")
async def login_submit(
    request: Request,
    db: Session = Depends(get_db),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    data = {
        "email": form_data.get("email", "").strip(),
        "password": form_data.get("password", ""),
    }
    form, errors = parse_form(LoginForm, data)

    if errors:
        return render(
            request,
            "auth/login.html",
            errors=errors,
            form_data=data,
            next=form_data.get("next", ""),
        )

    try:
        user, _token = authenticate_user(
            db,
            email=form.email,
            password=form.password,
            request=request,
        )
    except InvalidCredentialsError:
        return render(
            request,
            "auth/login.html",
            errors={"password": ["Неверный email или пароль"]},
            form_data=data,
            next=form_data.get("next", ""),
        )

    create_web_session(db, request, user.id)
    flash(request, "Добро пожаловать!", "success")

    next_url = form_data.get("next", "")
    if not next_url.startswith("/web/"):
        next_url = "/web/account"

    return RedirectResponse(next_url, status_code=303)


@router.get("/register")
def register_page(request: Request):
    return render(request, "auth/register.html")


@router.post("/register")
async def register_submit(
    request: Request,
    db: Session = Depends(get_db),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    data = {
        "email": form_data.get("email", "").strip(),
        "password": form_data.get("password", ""),
        "password_confirm": form_data.get("password_confirm", ""),
    }
    form, errors = parse_form(RegisterForm, data)

    if form is not None and form.password != form.password_confirm:
        errors.setdefault("password_confirm", []).append("Пароли не совпадают")
        form = None

    if errors:
        return render(
            request,
            "auth/register.html",
            errors=errors,
            form_data=data,
        )

    try:
        user, _token = register_user(
            db,
            email=form.email,
            password=form.password,
            request=request,
        )
    except EmailAlreadyExistsError:
        return render(
            request,
            "auth/register.html",
            errors={"email": ["Этот email уже зарегистрирован"]},
            form_data=data,
        )
    except WeakPasswordError as e:
        return render(
            request,
            "auth/register.html",
            errors={"password": [str(e)]},
            form_data=data,
        )

    create_web_session(db, request, user.id)
    flash(request, "Регистрация успешна!", "success")
    return RedirectResponse("/web/account", status_code=303)


@router.post("/logout")
async def logout_submit(
    request: Request,
    db: Session = Depends(get_db),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    user = get_web_user(db, request)
    destroy_web_session(db, request)

    if user is not None:
        info = get_client_info(request)
        write_event(
            db,
            UserEvents.LOGOUT,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
        )

    flash(request, "Вы вышли из аккаунта", "info")
    return RedirectResponse("/web/login", status_code=303)


@router.get("/account")
def account_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    return render(request, "account/profile.html", current_user=user)


@router.get("/account/sessions")
def account_sessions_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    sessions = db.execute(
        select(WebSession)
        .where(WebSession.user_id == user.id)
        .order_by(WebSession.last_seen_at.desc())
    ).scalars().all()

    current_session_id = request.session.get("session_id")

    return render(
        request,
        "account/sessions.html",
        current_user=user,
        sessions=sessions,
        current_session_id=current_session_id,
    )


@router.post("/account/sessions/{session_id}/revoke")
async def account_session_revoke(
    request: Request,
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    ws = db.execute(
        select(WebSession).where(
            WebSession.session_id == session_id,
            WebSession.user_id == user.id,
        )
    ).scalar_one_or_none()

    if ws is not None and ws.revoked_at is None:
        ws.revoked_at = _utcnow()
        db.commit()

        info = get_client_info(request)
        write_event(
            db,
            OAuthEvents.SESSION_REVOKED,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"web_session_id": session_id},
        )
        flash(request, "Сессия завершена", "success")

    return RedirectResponse("/web/account/sessions", status_code=303)


@router.get("/account/security")
def account_security_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    return render(
        request,
        "account/security.html",
        current_user=user,
    )


@router.post("/account/security")
async def account_security_submit(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    old_password = form_data.get("old_password", "")
    new_password = form_data.get("new_password", "")
    new_password_confirm = form_data.get("new_password_confirm", "")

    errors = {}

    if not verify_password(old_password, user.hashed_password):
        errors["old_password"] = ["Неверный текущий пароль"]

    if new_password != new_password_confirm:
        errors["new_password_confirm"] = ["Пароли не совпадают"]

    if not errors:
        try:
            validate_policy(new_password, user_inputs=[user.email])
        except WeakPasswordError as e:
            errors["new_password"] = [str(e)]

    if errors:
        return render(
            request,
            "account/security.html",
            current_user=user,
            errors=errors,
        )

    user.hashed_password = hash_password(new_password)
    db.commit()

    current_session_id = request.session.get("session_id")
    revoked = db.execute(
        update(WebSession).where(
            WebSession.user_id == user.id,
            WebSession.session_id != current_session_id,
            WebSession.revoked_at.is_(None),
        )
        .values(revoked_at=_utcnow())
    ).rowcount
    db.commit()

    info = get_client_info(request)
    write_event(
        db,
        UserEvents.PASSWORD_CHANGED,
        actor_id=user.id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={"sessions_revoked": revoked},
    )

    flash(request, "Пароль изменен. Остальные устройства разлогинены.", "success")
    return RedirectResponse("/web/account/security", status_code=303)
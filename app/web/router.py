from __future__ import annotations
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.service import (
    EmailAlreadyExistsError,
    register_user,
    authenticate_user,
    InvalidCredentialsError,
)
from app.core.passwords import WeakPasswordError, verify_password
from app.db.session import get_db
from app.models.user import User
from app.web.context import render
from app.web.csrf import verify_csrf
from app.web.flash import flash
from app.web.forms import LoginForm, RegisterForm, parse_form
from app.web.session import create_web_session, destroy_web_session, get_web_user

router = APIRouter(prefix="/web", tags=["web"])

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
    form, errors = parse_form(LoginForm. data)

    if errors:
        return render(
            request,
            "auth/login.html",
            errors=errors,
            form_date=data,
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

    destroy_web_session(db, request)
    flash(request, "Вы вышли из аккаунта", "info")
    return RedirectResponse("/web/login", status_code=303)
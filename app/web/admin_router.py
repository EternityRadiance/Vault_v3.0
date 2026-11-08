from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Form, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from math import ceil

import secrets
import uuid

from app.audit.events import AdminEvents
from app.audit.service import get_client_info, write_event
from app.core.passwords import hash_password
from app.db.session import get_db
from app.models.oauth_client import OAuthClient
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession
from app.web.audit_log import list_audit_events
from app.web.context import render
from app.web.csrf import verify_csrf
from app.web.deps import require_admin_web
from app.web.forms import parse_client_form
from app.web.flash import flash
from app.web.stats import (
    get_dashboard_counters,
    get_login_sparkline_meta,
    get_login_sparkline_points,
)

USERS_PAGE_SIZE = 25

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


router = APIRouter(
    prefix="/admin",
    tags=["web-admin"],
    dependencies=[Depends(require_admin_web)],
)

@router.get("")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    counters = get_dashboard_counters(db)
    sparkline_points = get_login_sparkline_points(db, days=7)
    sparkline_meta = get_login_sparkline_meta(db, days=7)
    return render(
        request,
        "admin/dashboard.html",
        current_user=user,
        active="dashboard",
        counters=counters,
        sparkline_points=sparkline_points,
        sparkline_meta=sparkline_meta,
    )

@router.get("/stats")
def stats_json(
    db: Session = Depends(get_db),
) -> dict:
    return get_dashboard_counters(db)

@router.get("/users")
def users_list(
    request: Request,
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    partial: int = Query(default=0, ge=0, le=1),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    q_norm = (q or "").strip()[:100]

    base_stmt = select(User)
    if q_norm:
        base_stmt = base_stmt.where(User.email.ilike(f"%{q_norm}%"))

    total = db.execute(
        select(func.count()).select_from(base_stmt.subquery())
    ).scalar_one()
    total_pages = max(1, ceil(total / USERS_PAGE_SIZE))
    page = min(page, total_pages)
    offset = (page - 1) * USERS_PAGE_SIZE

    users = db.execute(
        base_stmt.order_by(User.id).offset(offset).limit(USERS_PAGE_SIZE)
    ).scalars().all()

    context = {
        "current_user": user,
        "active": "users",
        "users": users,
        "q": q_norm,
        "page": page,
        "total_pages": total_pages,
        "total": total,
    }

    if partial:
        return render(request, "admin/_users_table.html", **context)

    return render(request, "admin/users.html", **context)

@router.get("/users/{user_id}")
def user_detail(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    target = db.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    audit_events = list_audit_events(db, actor_id=target.id, limit=50)

    return render(
        request,
        "admin/user_detail.html",
        current_user=user,
        active="users",
        target=target,
        audit_events=audit_events,
    )

@router.post("/users/{user_id}/disable")
async def user_disable(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    target = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == user.id:
        flash(request, "Нельзя заблокировать самого себя", "error")
        return RedirectResponse(f"/web/admin/users/{user_id}", status_code=303)

    if target.is_admin and target.is_active:
        active_admins = db.execute(
            select(func.count(User.id)).where(
                User.is_admin.is_(True), User.is_active.is_(True)
            )
        ).scalar_one()

        if active_admins <= 1:
            flash(request, "нельзя заблокировать последнего активного админа", "error")
            return RedirectResponse(f"/web/admin/users/{user_id}", status_code=303)

    if target.is_active:
        target.is_active = False
        db.commit()

        info = get_client_info(request)
        write_event(
            db,
            AdminEvents.USER_DISABLED,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"target_user_id": target.id, "target_email": target.email},
        )
        flash(request, f"Пользователь {target.email} заблокирован", "success")

    return RedirectResponse(f"/web/admin/users/{user_id}", status_code=303)


@router.post("/users/{user_id}/enable")
async def user_enable(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    target = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not target.is_active:
        target.is_active = True
        db.commit()

        info = get_client_info(request)
        write_event(
            db,
            AdminEvents.USER_ENABLED,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"target_user_id": target.id, "target_email": target.email},
        )
        flash(request, f"Пользователь {target.email} разблокирован", "success")

    return RedirectResponse(f"/web/admin/users/{user_id}", status_code=303)

@router.post("/users/{user_id}/revoke-sessions")
async def user_revoke_sessions(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web)
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    target = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    now = _utcnow()
    rt_count = db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == target.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount
    us_count = db.execute(
            update(UserSession)
            .where(UserSession.user_id == target.id, UserSession.revoked_at.is_(None))
            .values(revoked_at=now)
        ).rowcount
    db.commit()

    info = get_client_info(request)
    write_event(
        db,
        AdminEvents.USER_SESSIONS_REVOKED,
        actor_id=user.id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "target_user_id": target.id,
            "revoked_tokens_count": rt_count,
            "sessions_revoked": us_count,
        },
    )
    flash(
        request,
        f"Отозвано сессий: {us_count}, refresh-токенов: {rt_count}",
        "success",
    )
    return RedirectResponse(f"/web/admin/users/{user_id}", status_code=303)

@router.get("/clients")
def clients_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    clients = db.execute(
        select(OAuthClient).order_by(OAuthClient.id)
    ).scalars().all()

    return render(
        request,
        "admin/clients.html",
        current_user=user,
        active="clients",
        clients=clients,
    )

@router.get("/clients/new")
def client_new_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    return render(
        request,
        "admin/client_new.html",
        current_user=user,
        active="clients",
        form_data=None,
        errors=None,
    )

@router.post("/clients/new")
async def client_new_submit(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    raw = {
        "name": form_data.get("name", ""),
        "is_confidential": form_data.get("is_confidential", ""),
        "scopes": form_data.get("scopes", ""),
        "grant_types": form_data.get("grant_types", ""),
        "redirect_uris": form_data.get("redirect_uris", ""),
    }

    form, errors = parse_client_form(raw)

    if errors:
        return render(
            request,
            "admin/client_new.html",
            current_user=user,
            active="clients",
            form_data=raw,
            errors=errors,
        )

    raw_secret: str | None = None
    hashed_secret: str | None = None
    if form.is_confidential:
        raw_secret = secrets.token_urlsafe(48)
        hashed_secret = hash_password(raw_secret)

    client = OAuthClient(
        client_id=uuid.uuid4().hex,
        name=form.name,
        is_confidential=form.is_confidential,
        hashed_secret=hashed_secret,
        redirect_uris=form.redirect_uris,
        scopes=form.scopes,
        grant_types=form.grant_types,
        is_active=True,
    )
    db.add(client)
    db.flush()

    info = get_client_info(request)
    write_event(
        db,
        AdminEvents.CLIENT_CREATED,
        actor_id=user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "name": client.name,
            "is_confidential": form.is_confidential,
            "scopes": form.scopes,
            "grant_types": form.grant_types,
        },
    )

    if raw_secret:
        request.session["client_secret_once"] = {
            "client_pk": client.id,
            "client_id": client.client_id,
            "secret": raw_secret,
            "action": "created",
        }
        return RedirectResponse(
            f"/web/admin/clients/{client.id}/secret-shown",
            status_code=303,
        )

    flash(request, f"Клиент {client.name} создан (публичный, без секрета)", "success")
    return RedirectResponse(f"/web/admin/clients/{client.id}", status_code=303)

@router.get("/clients/{client_pk}/secret-shown")
def client_secret_shown(
    request: Request,
    client_pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    payload = request.session.pop("client_secret_once", None)

    if not payload or payload.get("client_pk") != client_pk:
        flash(request, "Секрет уже был показан или недоступен. Ротируйте заново.", "error")
        return RedirectResponse(f"/web/admin/clients/{client_pk}", status_code=303)

    return render(
        request,
        "admin/client_secret.html",
        current_user=user,
        active="clients",
        client_pk=client_pk,
        client_id=payload["client_id"],
        secret=payload["secret"],
        action=payload["action"],
    )

@router.get("/clients/{client_pk}")
def client_detail(
    request: Request,
    client_pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == client_pk)
    ).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    return render(
        request,
        "admin/client_detail.html",
        current_user=user,
        active="clients",
        client=client,
    )

@router.post("/clients/{client_pk}/rotate-secret")
async def client_rotate_secret(
    request: Request,
    client_pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == client_pk)
    ).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    if not client.is_confidential:
        flash(request, "Публичному клиенту секрет не нужен", "error")
        return RedirectResponse(f"web/admin/clients/{client_pk}", status_code=303)

    raw_secret = secrets.token_urlsafe(48)
    client.hashed_secret = hash_password(raw_secret)
    db.commit()

    info = get_client_info(request)
    write_event(
        db,
        AdminEvents.CLIENT_SECRET_ROTATED,
        actor_id=user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={"target_client_id": client.client_id},
    )

    request.session["client_secret_once"] = {
        "client_pk": client.id,
        "client_id": client.client_id,
        "secret": raw_secret,
        "action": "rotated",
    }
    return RedirectResponse(f"/web/admin/clients/{client.id}/secret-shown", status_code=303)

@router.post("/clients/{client_pk}/enable")
async def client_enable(
    request: Request,
    client_pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == client_pk)
    ).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client now found")

    if not client.is_active:
        client.is_active = True
        db.commit()
        info = get_client_info(request)
        write_event(
            db,
            AdminEvents.CLIENT_ENABLED,
            actor_id=user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"target_client_id": client.client_id},
        )
        flash(request, f"Клиент {client.name} включен", "success")

    return RedirectResponse(f"/web/admin/clients/{client_pk}", status_code=303)

@router.post("/clients/{client_pk}/disable")
async def client_disable(
    request: Request,
    client_pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin_web),
):
    form_data = await request.form()
    verify_csrf(request, form_data.get("csrf_token"))

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == client_pk)
    ).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client now found")

    if client.is_active:
        client.is_active = False
        db.commit()
        info = get_client_info(request)
        write_event(
            db,
            AdminEvents.CLIENT_DISABLED,
            actor_id=user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"target_client_id": client.client_id},
        )
        flash(request, f"Клиент {client.name} выключен", "success")

    return RedirectResponse(f"/web/admin/clients/{client_pk}", status_code=303)
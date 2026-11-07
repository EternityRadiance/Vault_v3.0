from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Form, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from math import ceil

from app.audit.events import AdminEvents
from app.audit.service import get_client_info, write_event
from app.db.session import get_db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_session import UserSession
from app.web.audit_log import list_audit_events
from app.web.context import render
from app.web.csrf import verify_csrf
from app.web.deps import require_admin_web
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
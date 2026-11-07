from __future__ import annotations
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.web.context import render
from app.web.deps import require_admin_web
from app.web.stats import (
    get_dashboard_counters,
    get_login_sparkline_meta,
    get_login_sparkline_points,
)
from app.models.user import User

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
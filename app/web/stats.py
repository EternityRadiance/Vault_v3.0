from __future__ import annotations
from datetime import datetime, timedelta, timezone
from datetime import date as _date
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.models.user_session import UserSession

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

def get_dashboard_counters(db: Session) -> dict[str, int]:
    """Подсчитывает сводные показатели для административной панели.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.

    Возвращает:
        Результат выполнения операции (тип: dict[str, int]).
    """
    users = db.execute(select(func.count(User.id))).scalar_one()
    clients = db.execute(select(func.count(OAuthClient.id))).scalar_one()
    active_sessions = db.execute(
        select(func.count(UserSession.id)).where(UserSession.revoked_at.is_(None))
    ).scalar_one()

    cutoff_24h = _utcnow() - timedelta(hours=24)
    events_24h = db.execute(
        select(func.count(AuditEvent.id)).where(AuditEvent.created_at >= cutoff_24h)
    ).scalar_one()

    return {
        "users": int(users or 0),
        "clients": int(clients or 0),
        "active_sessions": int(active_sessions or 0),
        "events_24h": int(events_24h or 0),
    }

def get_login_sparkline_points(
        db: Session,
        *,
        days: int = 7,
        width: int = 200,
        height: int = 50,
) -> str:
    """Формирует точки числа успешных входов для графика.

    Параметры:
        db (Session): сессия базы данных для получения числа успешных входов..
        days (int): число дней, включаемых в диапазон графика..
        width (int): ширина области графика в пикселях..
        height (int): высота области графика в пикселях..

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    today = _utcnow().date()
    start = today - timedelta(days=days - 1)

    rows = db.execute(
        select(
            func.date(AuditEvent.created_at).label("d"),
            func.count(AuditEvent.id).label("c"),
        )
        .where(
            AuditEvent.event_type == "user.login.success",
            AuditEvent.created_at >= datetime(start.year, start.month, start.day),
        )
        .group_by("d")
        .order_by("d")
    ).all()

    counts_by_date = {}
    for d, c in rows:
        if isinstance(d, str):
            try:
                d = _date.fromisoformat(d)
            except ValueError:
                continue
        counts_by_date[d] = int(c)

    series = [counts_by_date.get(start + timedelta(days=i), 0) for i in range(days)]
    max_count = max(series) or 1

    n = len(series)
    if n == 1:
        return f"0,{height} {width},{height}"

    parts =[]
    for i, value in enumerate(series):
        x = round(i * (width / (n - 1)), 2)
        y = round(height - (value / max_count) * height, 2)
        parts.append(f"{x},{y}")
    return " ".join(parts)

def get_login_sparkline_meta(
        db: Session,
        *,
        days: int = 7,
) -> dict[str, int | str]:
    """Возвращает метаданные диапазона графика успешных входов.

    Параметры:
        db (Session): сессия базы данных для подсчета успешных входов..
        days (int): число дней, включаемых в диапазон графика..

    Возвращает:
        Результат выполнения операции (тип: dict[str, int | str]).
    """
    today = _utcnow().date()
    start = today - timedelta(days=days - 1)

    rows = db.execute(
        select(
            func.date(AuditEvent.created_at).label("d"),
            func.count(AuditEvent.id).label("c"),
        )
        .where(
            AuditEvent.event_type == "user.login.success",
            AuditEvent.created_at >= datetime(start.year, start.month, start.day),
        )
        .group_by("d")
    ).all()

    counts_by_date = {}
    for d, c in rows:
        if isinstance(d, str):
            try:
                d = _date.fromisoformat(d)
            except ValueError:
                continue
        counts_by_date[d] = int(c)

    series = [counts_by_date.get(start + timedelta(days=i), 0) for i in range(days)]

    return {
        "total": sum(series),
        "max_day_value": max(series) if series else 0,
        "first_date": start.isoformat(),
        "last_date": today.isoformat(),
    }
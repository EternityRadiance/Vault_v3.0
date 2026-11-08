from __future__ import annotations
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent

PAGE_SIZE = 50

def list_audit_events(
        db: Session,
        *,
        actor_id: int | None = None,
        event_type: str | None = None,
        ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: int = PAGE_SIZE,
        offset: int = 0,
) -> list[AuditEvent]:
    """Загружает и фильтрует записи аудита для административного интерфейса.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        actor_id (int | None): идентификатор пользователя, выполнившего действие.
        event_type (str | None): тип события аудита.
        ip (str | None): IP-адрес клиента.
        date_from (datetime | None): начальная дата диапазона фильтра.
        date_to (datetime | None): конечная дата диапазона фильтра.
        limit (int): максимальное количество возвращаемых записей.
        offset (int): число пропускаемых записей при пагинации.

    Возвращает:
        Результат выполнения операции (тип: list[AuditEvent]).
    """
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if actor_id is not None:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if ip:
        stmt = stmt.where(AuditEvent.ip == ip)
    if date_from:
        stmt = stmt.where(AuditEvent.created_at >= date_from)
    if date_to:
        stmt = stmt.where(AuditEvent.created_at <= date_to)
    stmt = stmt.offset(offset).limit(limit)

    return list(db.execute(stmt).scalars().all())
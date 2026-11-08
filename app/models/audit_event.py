from datetime import datetime, timezone
from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    event_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    metadata_json: Mapped[dict | None] = mapped_column(
        "metadata", JSON, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False, index=True
    )

    def __repr__(self) -> str:
        """Формирует строковое представление объекта для отладки.

        Параметры:
            self (AuditEvent): экземпляр класса AuditEvent, переданный Python.

        Возвращает:
            Результат выполнения операции (тип: str).
        """
        return (
            f"<AuditEvent id={self.id} type={self.event_type!r} "
            f"actor={self.actor_id}>"
        )
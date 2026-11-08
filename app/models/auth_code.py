from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

class AuthCode(Base):
    __tablename__ = "auth_codes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(String(10), nullable=True)

    nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False
    )

    def __repr__(self) -> str:
        """Формирует строковое представление объекта для отладки.

        Параметры:
            self (AuthCode): экземпляр класса AuthCode, переданный Python.

        Возвращает:
            Результат выполнения операции (тип: str).
        """
        return (
            f"<AuthCode id={self.id} client_id={self.client_id!r} "
            f"used={self.used_at is not None}>"
        )
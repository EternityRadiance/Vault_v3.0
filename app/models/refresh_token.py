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

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    replaced_by_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False, index=True
    )

    def __repr__(self) -> str:
        """Формирует строковое представление объекта для отладки.

        Параметры:
            self (RefreshToken): экземпляр класса RefreshToken, переданный Python.

        Возвращает:
            Результат выполнения операции (тип: str).
        """
        return(
            f"<RefreshToken id={self.id} jti={self.jti!r} "
            f"family={self.family_id!r}>"
        )
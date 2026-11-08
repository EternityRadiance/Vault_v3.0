from datetime import datetime, timezone
from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

def _utcnow() -> datetime:
    """Возвращает текущее время в UTC без часового пояса.

    Возвращает:
        Результат выполнения операции (тип: datetime).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    client_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    is_confidential: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    hashed_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)

    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    scopes: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["openid"], nullable=False
    )

    grant_types: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: ["authorization_code", "refresh_token"],
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow, nullable=False
    )

    def __repr__(self) -> str:
        """Формирует строковое представление объекта для отладки.

        Параметры:
            self (OAuthClient): экземпляр класса OAuthClient, переданный Python.

        Возвращает:
            Результат выполнения операции (тип: str).
        """
        return f"<OAuthClient client_id={self.client_id!r} name={self.name!r}>"
from __future__ import annotations
from typing import Any
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent

FORBIDDEN_METADATA_KEYS = frozenset({
    "password",
    "hashed_password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "pepper",
    "jwt",
})

def write_event(
        db: Session,
        event_type: str,
        *,
        actor_id: int | None = None,
        client_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
) -> AuditEvent:

    """Проверяет метаданные и сохраняет запись события аудита.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        event_type (str): тип события аудита.
        actor_id (int | None): идентификатор пользователя, выполнившего действие.
        client_id (str | None): идентификатор OAuth-клиента.
        ip (str | None): IP-адрес клиента.
        user_agent (str | None): значение заголовка User-Agent клиента.
        metadata (dict[str, Any] | None): метаданные события или операции.

    Возвращает:
        Результат выполнения операции (тип: AuditEvent).
    """
    if metadata:
        forbidden = FORBIDDEN_METADATA_KEYS & metadata.keys()
        if forbidden:
            raise ValueError(
                f"Аудит не должен содержать секреты: {sorted(forbidden)}"
            )

    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        metadata_json=metadata,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def get_client_info(request) -> dict[str, str | None]:

    """Извлекает IP-адрес и User-Agent HTTP-клиента из запроса.

    Параметры:
        request: HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: dict[str, str | None]).
    """
    ip = None
    user_agent = None

    if request is not None:
        if request.client is not None:
            ip = request.client.host
        user_agent = request.headers.get("user-agent")

    return{"ip": ip, "user_agent": user_agent}
from __future__ import annotations
from ariadne import MutationType, ObjectType, QueryType, convert_kwargs_to_snake_case
from sqlalchemy import select
from sqlalchemy.orm import Session
from uuid import uuid4
import json

from datetime import datetime, timezone
from sqlalchemy import update
from app.audit.events import OAuthEvents

from app.audit.events import UserEvents
from app.audit.service import get_client_info, write_event
from app.auth.service import (
    EmailAlreadyExistsError,
    register_user,
)
from app.core.passwords import WeakPasswordError
from app.models.oauth_client import OAuthClient
from app.models.audit_event import AuditEvent
from app.models.user import User

from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession

query = QueryType()
mutation = MutationType()
audit_event_type = ObjectType("AuditEvent")


@audit_event_type.field("metadata")
def resolve_audit_metadata(event, info):
    """Сериализует метаданные записи аудита для поля GraphQL.

    Параметры:
        event: запись аудита, для которой вычисляется значение поля.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: str | NoneType).
    """
    if event.metadata_json is None:
        return None
    return json.dumps(event.metadata_json, ensure_ascii=False)

@query.field("users")
@convert_kwargs_to_snake_case
def resolve_users(obj, info, search=None, limit=50, offset=0):

    """Возвращает страницу пользователей с необязательной фильтрацией по поисковой строке.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        search: строка поиска для фильтрации записей.
        limit: максимальное количество возвращаемых записей.
        offset: число пропускаемых записей при пагинации.

    Возвращает:
        Результат выполнения операции (тип: list).
    """
    db: Session = info.context["db"]

    stmt = select(User).order_by(User.id)
    if search:
        stmt = stmt.where(User.email.ilike(f"%{search}"))
    stmt = stmt.offset(offset).limit(limit)

    return db.execute(stmt).scalars().all()

@query.field("clients")
def resolve_clients(obj, info):

    """Возвращает список OAuth-клиентов для поля GraphQL.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: list).
    """
    db: Session = info.context["db"]
    return db.execute(select(OAuthClient).order_by(OAuthClient.id)).scalars().all()

@query.field("auditEvents")
@convert_kwargs_to_snake_case
def resolve_audit_events(obj, info, event_type=None, limit=100, offset=0):

    """Возвращает страницу событий аудита с необязательной фильтрацией по типу.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        event_type: тип события аудита.
        limit: максимальное количество возвращаемых записей.
        offset: число пропускаемых записей при пагинации.

    Возвращает:
        Результат выполнения операции (тип: list).
    """
    db: Session = info.context["db"]

    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    stmt = stmt.offset(offset).limit(limit)

    return db.execute(stmt).scalars().all()

@query.field("me")
def resolve_me(obj, info):
    """Возвращает текущего пользователя из контекста GraphQL.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    return info.context["user"]



@mutation.field("registerUser")
@convert_kwargs_to_snake_case
def resolve_register_user(obj, info, email, password):

    """Регистрирует пользователя через GraphQL и формирует ответ с access token.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        email: адрес электронной почты пользователя.
        password: пароль пользователя.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    db: Session = info.context["db"]
    request = info.context.get("request")

    try:
        user, token = register_user(
            db,
            email=email,
            password=password,
            request=request,
        )
    except EmailAlreadyExistsError as e:
        raise ValueError(f"Email already registered") from e
    except WeakPasswordError as e:
        raise ValueError(str(e)) from e

    return {"access_token": token, "token_type": "bearer"}

@query.field("sessions")
@convert_kwargs_to_snake_case
def resolve_sessions(obj, info, user_id):
    """Возвращает пользовательские сессии для поля GraphQL.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        user_id: идентификатор пользователя в базе данных.

    Возвращает:
        Результат выполнения операции (тип: list).
    """
    db: Session = info.context["db"]
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        raise ValueError("invalid user_id")

    return db.execute(
        select(UserSession)
        .where(UserSession.user_id == uid)
        .order_by(UserSession.created_at.desc())
    ).scalars().all()


@query.field("refreshTokens")
@convert_kwargs_to_snake_case
def resolve_refresh_tokens(obj, info, user_id):
    """Возвращает refresh-токены пользователя для поля GraphQL.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        user_id: идентификатор пользователя в базе данных.

    Возвращает:
        Результат выполнения операции (тип: list).
    """
    db: Session = info.context["db"]
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        raise ValueError("invalid user_id")

    return db.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == uid)
        .order_by(RefreshToken.created_at.desc())
    ).scalars().all()

@mutation.field("createClient")
@convert_kwargs_to_snake_case
def resolve_create_client(
    obj, info, name,
    is_confidential=True,
    scopes=None,
    grant_types=None,
    redirect_uris=None,
):
    """Создаёт OAuth-клиента с заданными grant types, scope и redirect URI.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        name: имя ресурса или операции.
        is_confidential: признак конфиденциального OAuth-клиента.
        scopes: список выданных OAuth-разрешений.
        grant_types: разрешенные типы OAuth grant.
        redirect_uris: разрешенные redirect URI OAuth-клиента.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    import secrets
    from app.audit.events import OAuthEvents
    from app.audit.service import get_client_info, write_event
    from app.core.passwords import hash_password

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    scopes = scopes or ["openid"]
    grant_types = grant_types or ["authorization_code", "refresh_token"]
    redirect_uris = redirect_uris or []

    raw_secret: str | None = None
    hashed_secret: str | None = None
    if is_confidential:
        raw_secret = secrets.token_urlsafe(48)
        hashed_secret = hash_password(raw_secret)

    client = OAuthClient(
        client_id=uuid4().hex,
        name=name,
        is_confidential=is_confidential,
        hashed_secret=hashed_secret,
        redirect_uris=redirect_uris,
        scopes=scopes,
        grant_types=grant_types,
        is_active=True,
    )
    db.add(client)
    db.flush()

    info_dict = get_client_info(request)
    write_event(
        db,
        OAuthEvents.CLIENT_CREATED,
        actor_id=current_user.id,
        client_id=client.client_id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={
            "name": client.name,
            "is_confidential": is_confidential,
            "scopes": scopes,
            "grant_types": grant_types,
        },
    )

    return {
        "client_id": str(client.id),
        "client_secret": raw_secret,
    }

@mutation.field("disableUser")
@convert_kwargs_to_snake_case
def resolve_disable_user(obj, info, user_id):

    """Отключает учетную запись пользователя через административную GraphQL-операцию.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        user_id: идентификатор пользователя в базе данных.

    Возвращает:
        Результат выполнения операции (тип: User).
    """
    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        raise ValueError("invalid user id")

    target = db.execute(
        select(User).where(User.id == uid)
    ).scalar_one_or_none()

    if target is None:
        raise ValueError("User not found")

    if not target.is_active:
        return target

    target.is_active = False

    info_dict = get_client_info(request)
    write_event(
        db,
        UserEvents.DISABLED,
        actor_id=current_user.id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"target_user_id": target.id, "target_email": target.email},
    )

    return target

@mutation.field("revokeUserSessions")
@convert_kwargs_to_snake_case
def resolve_revoke_user_sessions(obj, info, user_id):
    

    """Отзывает пользовательские сессии через административную GraphQL-операцию.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        user_id: идентификатор пользователя в базе данных.

    Возвращает:
        Результат выполнения операции (тип: int).
    """
    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        raise ValueError("invalid user_id")

    target = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if target is None:
        raise ValueError("User not found")

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    rt_result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == uid, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    us_result = db.execute(
        update(UserSession)
        .where(UserSession.user_id == uid, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.commit()

    count = us_result.rowcount

    info_dict = get_client_info(request)
    write_event(
        db,
        OAuthEvents.SESSION_REVOKED,
        actor_id=current_user.id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={
            "target_user_id": uid,
            "refresh_tokens_revoked": rt_result.rowcount,
            "sessions_revoked": count,
        },
    )

    return count

@mutation.field("rotateClientSecret")
@convert_kwargs_to_snake_case
def resolve_rotate_client_secret(obj, info, client_id):
    """Создаёт новый секрет OAuth-клиента через административную GraphQL-операцию.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        client_id: идентификатор OAuth-клиента.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    import secrets
    from app.audit.events import OAuthEvents
    from app.audit.service import get_client_info, write_event
    from app.core.passwords import hash_password

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        cid = int(client_id)
    except (TypeError, ValueError):
        raise ValueError("invalid clientId")

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == cid)
    ).scalar_one_or_none()
    if client is None:
        raise ValueError("Client not found")

    if not client.is_confidential:
        raise ValueError("Cannot rotate secret for public client")

    raw_secret = secrets.token_urlsafe(48)
    client.hashed_secret = hash_password(raw_secret)
    db.commit()
    db.refresh(client)

    info_dict = get_client_info(request)
    write_event(
        db,
        OAuthEvents.CLIENT_SECRET_ROTATED,
        actor_id=current_user.id,
        client_id=client.client_id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"target_client_id": client.client_id},
    )

    return {"client_id": str(client.id), "client_secret": raw_secret}


@mutation.field("enableClient")
@convert_kwargs_to_snake_case
def resolve_enable_client(obj, info, client_id):
    """Включает OAuth-клиента через административную GraphQL-операцию.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        client_id: идентификатор OAuth-клиента.

    Возвращает:
        Результат выполнения операции (тип: OAuthClient | None).
    """
    from app.audit.events import OAuthEvents
    from app.audit.service import get_client_info, write_event

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        cid = int(client_id)
    except (TypeError, ValueError):
        raise ValueError("invalid clientId")

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == cid)
    ).scalar_one_or_none()
    if client is None:
        raise ValueError("Client not found")

    if client.is_active:
        return client

    client.is_active = True
    db.commit()
    db.refresh(client)

    info_dict = get_client_info(request)
    write_event(
        db,
        OAuthEvents.CLIENT_ENABLED,
        actor_id=current_user.id,
        client_id=client.client_id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"target_client_id": client.client_id},
    )

    return client


@mutation.field("disableClient")
@convert_kwargs_to_snake_case
def resolve_disable_client(obj, info, client_id):
    """Отключает OAuth-клиента через административную GraphQL-операцию.

    Параметры:
        obj: родительский объект поля, переданный GraphQL-фреймворком.
        info: контекст выполнения поля, переданный GraphQL-фреймворком.
        client_id: идентификатор OAuth-клиента.

    Возвращает:
        Обновлённый OAuth-клиент (тип: OAuthClient).
    """
    from app.audit.events import OAuthEvents
    from app.audit.service import get_client_info, write_event

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        cid = int(client_id)
    except (TypeError, ValueError):
        raise ValueError("invalid clientId")

    client = db.execute(
        select(OAuthClient).where(OAuthClient.id == cid)
    ).scalar_one_or_none()
    if client is None:
        raise ValueError("Client not found")

    if not client.is_active:
        return client

    client.is_active = False
    db.commit()
    db.refresh(client)

    info_dict = get_client_info(request)
    write_event(
        db,
        OAuthEvents.CLIENT_DISABLED,
        actor_id=current_user.id,
        client_id=client.client_id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"target_client_id": client.client_id},
    )

    return client
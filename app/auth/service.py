from __future__ import annotations
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import UserEvents
from app.audit.service import write_event, get_client_info
from app.core.jwt import create_access_token
from app.core.passwords import (
    hash_password,
    validate_policy,
    verify_password,
)
from app.models.user import User

class EmailAlreadyExistsError(ValueError):
    pass

class InvalidCredentialsError(ValueError):
    pass

def register_user(
        db: Session,
        *,
        email: str,
        password: str,
        request=None,
) -> tuple[User, str]:

    """Создаёт пользователя после проверки email и пароля, записывает событие аудита и выдаёт токен доступа.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        email (str): адрес электронной почты пользователя.
        password (str): пароль пользователя.
        request: HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: tuple[User, str]).
    """
    email_norm = email.strip().lower()

    existing = db.execute(
        select(User).where(User.email == email_norm)
    ).scalar_one_or_none()
    if existing is not None:
        raise EmailAlreadyExistsError("Email already registered")

    validate_policy(password, user_inputs=[email_norm])

    user = User(
        email=email_norm,
        hashed_password=hash_password(password),
        is_active=True,
        is_admin=False,
    )
    db.add(user)
    db.flush()

    info = get_client_info(request) if request is not None else {"ip": None, "user_agent": None}
    write_event(
        db,
        UserEvents.CREATED,
        actor_id=user.id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={"email": user.email},
    )

    token = create_access_token(sub=user.id)
    return user, token

def authenticate_user(
        db: Session,
        *,
        email: str,
        password: str,
        request=None,
) -> tuple[User, str]:

    """Проверяет учетные данные и активность пользователя, записывает результат входа и выдаёт токен доступа.

    Параметры:
        db (Session): сессия базы данных для чтения и сохранения данных.
        email (str): адрес электронной почты пользователя.
        password (str): пароль пользователя.
        request: HTTP-запрос, переданный веб-фреймворком.

    Возвращает:
        Результат выполнения операции (тип: tuple[User, str]).
    """
    email_norm = email.strip().lower()

    user = db.execute(
        select(User).where(User.email == email_norm)
    ).scalar_one_or_none()


    info = get_client_info(request) if request is not None else {"ip": None, "user_agent": None}

    if user is None:
        write_event(
            db,
            UserEvents.LOGIN_FAILURE,
            actor_id=None,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"email": email_norm, "reason": "unknown_email"},
        )
        raise InvalidCredentialsError("Invalid credentials")

    if not verify_password(password, user.hashed_password):
        write_event(
            db,
            UserEvents.LOGIN_FAILURE,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"email": email_norm, "reason": "bad_password"},
        )
        raise InvalidCredentialsError("Invalid credentials")

    if not user.is_active:
        write_event(
            db,
            UserEvents.LOGIN_FAILURE,
            actor_id=user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"email": email_norm, "reason": "inactive"},
        )
        raise InvalidCredentialsError("Invalid credentials")
    
    write_event(
        db,
        UserEvents.LOGIN_SUCCESS,
        actor_id=user.id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={"email": email_norm},
    )

    token = create_access_token(sub=user.id)
    return user, token
    
from __future__ import annotations
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from zxcvbn import zxcvbn

from app.config import settings

class WeakPasswordError(ValueError):
    pass

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

def hash_password(password: str) -> str:

    """Хеширует пароль с добавлением pepper приложения.

    Параметры:
        password (str): пароль пользователя.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    if not isinstance(password, str) or not password:
        raise WeakPasswordError("Пароль не может быть пустым.")

    peppered = password + settings.password_pepper
    return _hasher.hash(peppered)

def verify_password(password: str, hashed: str) -> bool:
    """Сверяет пароль с сохранённым хешем.

    Параметры:
        password (str): пароль пользователя.
        hashed (str): сохраненный хеш пароля для сравнения.

    Возвращает:
        Результат выполнения операции (тип: bool).
    """
    if not password or not hashed:
        return False

    peppered = password + settings.password_pepper
    try:
        _hasher.verify(hashed, peppered)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def validate_policy(password: str, user_inputs: list[str] | None = None) -> None:
    """Проверяет длину и стойкость пароля с учётом пользовательских данных.

    Параметры:
        password (str): пароль пользователя.
        user_inputs (list[str] | None): список значений для оценки стойкости пароля.

    Возвращает:
        None (значение не возвращается).
    """
    if not isinstance(password, str) or not password:
        raise WeakPasswordError("Пароль не может быть пустым.")

    if len(password) < settings.password_min_length:
        raise WeakPasswordError(
            f"Пароль не должен быть короче {settings.password_min_length} символов."
        )

    result = zxcvbn(password, user_inputs=user_inputs or [])

    if result["score"] < 3:
        feedback = result.get("feedback", {})
        hint = feedback.get("warning") or "Пароль слишком предсказуемый."
        raise WeakPasswordError(
            f"Слишком слабый пароль: {hint}. "
            f"Оценка стойкости: {result['score']}/4 (требуется >= 3)."
        )
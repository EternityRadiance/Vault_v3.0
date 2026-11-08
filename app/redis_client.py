from __future__ import annotations
from functools import lru_cache
import redis

from app.config import settings

@lru_cache(maxsize=1)
def get_redis() -> redis.Redis:
    """Создаёт и возвращает кэшируемое подключение Redis с настройками приложения.

    Возвращает:
        Результат выполнения операции (тип: redis.Redis).
    """
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
    )

def blacklist_jti(jti: str, ttl_sec: int) -> None:
    """Добавляет идентификатор JWT в Redis-список отозванных токенов на заданный срок.

    Параметры:
        jti (str): идентификатор JWT (claim jti), который нужно добавить в список отозванных..
        ttl_sec (int): срок действия в секундах.

    Возвращает:
        None (значение не возвращается).
    """
    if ttl_sec <= 0:
        return
    get_redis().setex(f"revoked:{jti}", ttl_sec, "1")

def is_blacklisted(jti: str) -> bool:
    """Проверяет, находится ли идентификатор JWT в Redis-списке отозванных токенов.

    Параметры:
        jti (str): идентификатор JWT (claim jti), наличие которого проверяется в списке отозванных..

    Возвращает:
        Результат выполнения операции (тип: bool).
    """
    return get_redis().exists(f"revoked:{jti}") == 1
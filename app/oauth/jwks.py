from __future__ import annotations

import base64
from functools import lru_cache

from fastapi import APIRouter

from app.config import settings
from app.core.security.jwt_rsa import load_public_key

router = APIRouter(tags=["oauth"])

def _b64url_uint(n: int) -> str:
    """Кодирует целое число в Base64 URL-safe для представления параметра RSA-ключа.

    Параметры:
        n (int): целое число для кодирования.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    length = (n.bit_length() + 7) // 8
    raw = n.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

@lru_cache(maxsize=1)
def build_jwks() -> dict:
    """Строит набор открытых ключей JWKS для проверки подписей токенов.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    public_key = load_public_key()
    numbers = public_key.public_numbers()

    jwk_dict = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": settings.rsa_key_id,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    return {"keys": [jwk_dict]}

@router.get("/.well-known/jwks.json", include_in_schema=False)
def get_jwks() -> dict:
    """Возвращает набор открытых ключей JWKS в HTTP-ответе.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    return build_jwks()

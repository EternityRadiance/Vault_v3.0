"""
Проверка OAuth2 + JWKS: password grant → JWKS verify.

Находит конфиденциального клиента в БД, ротирует client_secret,
регистрирует тестового пользователя (если нет), получает access_token,
проверяет подпись по JWKS.

Запуск: python examples/check_oauth.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
from jose import jwt, jwk
from sqlalchemy import select

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.db.session import SessionLocal  # noqa: E402
from app.models.oauth_client import OAuthClient  # noqa: E402
from app.models.user import User  # noqa: E402


VAULT = "http://127.0.0.1:8000"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Very strong admin password"
TEST_EMAIL = "oauth-test@example.com"
TEST_PASSWORD = "some long password 12345"


def find_client() -> OAuthClient:
    """Находит OAuth-клиента по идентификатору в конфигурации демонстрационного приложения.

    Возвращает:
        Результат выполнения операции (тип: OAuthClient).
    """
    db = SessionLocal()
    try:
        for c in db.execute(select(OAuthClient).where(OAuthClient.is_confidential.is_(True))).scalars():
            if "password" in (c.grant_types or []):
                return c
        raise SystemExit("[-] No confidential client with password grant")
    finally:
        db.close()


def rotate_secret(client_id: int) -> str:
    """Выполняет ротацию секрета OAuth-клиента.

    Параметры:
        client_id (int): идентификатор OAuth-клиента.

    Возвращает:
        Результат выполнения операции (тип: str).
    """
    admin = httpx.post(
        f"{VAULT}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    ).json()["access_token"]

    r = httpx.post(
        f"{VAULT}/graphql/",
        json={"query": f'mutation {{ rotateClientSecret(clientId: "{client_id}") {{ clientSecret }} }}'},
        headers={"Authorization": f"Bearer {admin}"},
    )
    return r.json()["data"]["rotateClientSecret"]["clientSecret"]


def ensure_user() -> None:
    """Обеспечивает наличие пользователя в демонстрационном приложении.

    Возвращает:
        None (значение не возвращается).
    """
    db = SessionLocal()
    try:
        if db.execute(select(User).where(User.email == TEST_EMAIL)).scalar_one_or_none():
            return
    finally:
        db.close()

    r = httpx.post(
        f"{VAULT}/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    if r.status_code not in (200, 201):
        raise SystemExit(f"[-] register failed: {r.text}")


def main() -> None:
    """Запускает основную операцию сценария командной строки.

    Возвращает:
        None (значение не возвращается).
    """
    client = find_client()
    print(f"[=] client: {client.client_id} ({client.name})")

    secret = rotate_secret(client.id)
    print("[+] secret rotated")

    ensure_user()
    print(f"[=] user: {TEST_EMAIL}")

    r = httpx.post(
        f"{VAULT}/oauth/token",
        data={
            "grant_type": "password",
            "client_id": client.client_id,
            "client_secret": secret,
            "username": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "scope": "openid email",
        },
    )
    if r.status_code != 200:
        raise SystemExit(f"[-] token failed: {r.text}")

    token = r.json()["access_token"]
    print(f"[+] access_token: {len(token)} chars")

    jwks = httpx.get(f"{VAULT}/.well-known/jwks.json").json()
    header = jwt.get_unverified_header(token)
    key_data = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

    payload = jwt.decode(
        token,
        jwk.construct(key_data, algorithm="RS256"),
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_iss": False},
    )
    print(f"[+] verified via JWKS: sub={payload['sub']}, scope={payload.get('scope')}")


if __name__ == "__main__":
    main()
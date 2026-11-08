from __future__ import annotations
from fastapi import APIRouter

from app.config import settings

router = APIRouter(tags=["oauth"])

@router.get("/.well-known/openid-configuration", include_in_schema=False)
def get_openid_configuration() -> dict:
    """Формирует документ обнаружения OpenID Connect с адресами и поддерживаемыми возможностями сервера.

    Возвращает:
        Результат выполнения операции (тип: dict).
    """
    issuer = settings.issuer.rstrip("/")

    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "introspection_endpoint": f"{issuer}/oauth/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "password",
            "client_credentials",
        ],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "subject_types_supported": ["public"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat",
            "email", "email_verified",
            "name", "preferred_username"
        ],
    }
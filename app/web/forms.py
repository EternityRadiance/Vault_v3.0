from __future__ import annotations
from urllib.parse import urlparse
from pydantic import BaseModel, EmailStr, Field, ValidationError

class LoginForm(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

class RegisterForm(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)
    password_confirm : str = Field(..., min_length=1)

class ChangePasswordForm(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)
    new_password_confirm: str = Field(..., min_length=1)

class ClientForm(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    is_confidential: bool = True
    scopes: list[str] = Field(default_factory=lambda: ["openid"])
    grant_types: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    redirect_uris: list[str] = Field(default_factory=list)

def parse_form(form_class, data: dict) -> tuple[BaseModel | None, dict[str, list[str]]]:
    try:
        return form_class(**data), {}
    except ValidationError as e:
        errors: dict[str, list[str]] = {}
        for err in e.errors():
            field = err["loc"][0]
            errors.setdefault(field, []).append(err["msg"])
        return None, errors


ALLOWED_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})
ALLOWED_GRANT_TYPES = frozenset(
    {"authorization_code", "refresh_token", "password", "client_credentials"}
)

def _split_space(value: str | None) -> list[str]:
    if not value:
        return []
    return [s for s in value.replace(",", " ").split() if s]

def _split_lines(value: str | None) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]

def _is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def parse_client_form(raw: dict) -> tuple[ClientForm | None, dict[str, list[str]]]:
    errors: dict[str, list[str]] = {}

    data = {
        "name": (raw.get("name") or "").strip(),
        "is_confidential": raw.get("is_confidential") == "on",
        "scopes": _split_space(raw.get("scopes")),
        "grant_types": _split_space(raw.get("grant_types")),
        "redirect_uris": _split_lines(raw.get("redirect_uris")),
    }

    try:
        form = ClientForm(**data)
    except ValidationError as e:
        for err in e.errors():
            field = err["loc"][0]
            errors.setdefault(field, []).append(err["msg"])
        return None, errors

    unknown_scopes = set(form.scopes) - ALLOWED_SCOPES
    if unknown_scopes:
        errors.setdefault("scopes", []).append(
            f"Недопустимые scopes: {sorted(unknown_scopes)}. "
            f"Разрешены: {sorted(ALLOWED_SCOPES)}."
        )

    unknown_grants = set(form.grant_types) - ALLOWED_GRANT_TYPES
    if unknown_grants:
        errors.setdefault("grant_types", []).append(
            f"Недопустимые grant_types: {sorted(unknown_grants)}. "
            f"Разрешены: {sorted(ALLOWED_GRANT_TYPES)}."
        )

    if not form.scopes:
        errors.setdefault("scopes", []).append("Нужен хотя бы один scope.")

    if not form.grant_types:
        errors.setdefault("grant_types", []).append("Нужен хотя бы один grant_type.")

    for uri in form.redirect_uris:
        if not _is_valid_http_url(uri):
            errors.setdefault("redirect_uris", []).append(
                f"Невалидный redirect_uri (нужен http/https с хостом): {uri!r}"
            )

    if "authorization_code" in form.grant_types and not form.redirect_uris:
        errors.setdefault("redirect_uris", []).append(
            "Для grant_type=authorization_code нужен хотя бы один redirect_uri."
        )

    if errors:
        return None, errors
    return form, {}
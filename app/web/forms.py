from __future__ import annotations

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

def parse_form(form_class, data: dict) -> tuple[BaseModel | None, dict[str, list[str]]]:
    try:
        return form_class(**data), {}
    except ValidationError as e:
        errors: dict[str, list[str]] = {}
        for err in e.errors():
            field = err["loc"][0]
            errors.setdefault(field, []).append(err["msg"])
        return None, errors
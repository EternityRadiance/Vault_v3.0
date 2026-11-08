from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(
        ...,
        description="Подключение SQLAlchemy"
    )

    password_pepper: str = Field(..., min_length=32)
    password_min_length: int = Field(12, ge=8, le=128)

    environment: str = "development"
    app_name: str = "Vault"

    redis_url: str = "redis://localhost:6379/0"
    issuer: str = "http://127.0.0.1:8000"
    rsa_key_path: str = "./keys/rsa_private.pem"
    rsa_key_id: str = "vault-key-1"
    access_token_ttl_sec: int = 900
    refresh_token_ttl_days: int = 30
    auth_code_ttl_sec: int = 60
    pkce_required_for_public: bool = True
    consent_ttl_sec: int = 300

    session_secret: str = Field(..., min_length=32)
    session_cookie_name: str = "vault_session"
    session_ttl_min: int = 30

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def session_cookie_secure(self) -> bool:
        return self.is_production

settings = Settings()
from __future__ import annotations

from functools import lru_cache

from pydantic import Field, Json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "local"
    log_level: str = "INFO"
    http_port: int = 8001

    database_url: str = Field(
        default="postgresql+asyncpg://auth:auth@localhost:5432/auth_db"
    )

    jwt_private_key_path: str = "./keys/jwt_private.pem"
    jwt_public_key_path: str = "./keys/jwt_public.pem"
    jwt_kid: str = "auth-key-1"
    jwt_issuer: str = "auth-service"
    jwt_ttl_seconds: int = 900

    service_clients: Json[dict[str, str]] = Field(default="{}")
    service_token_ttl_seconds: int = 900


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

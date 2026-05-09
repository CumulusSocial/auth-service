from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from testcontainers.postgres import PostgresContainer


@pytest.fixture(scope="session")
def rsa_keypair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    keys_dir = tmp_path_factory.mktemp("keys")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv = keys_dir / "jwt_private.pem"
    pub = keys_dir / "jwt_public.pem"
    priv.write_bytes(priv_pem)
    pub.write_bytes(pub_pem)
    return priv, pub


@pytest.fixture(scope="session")
def postgres_url() -> AsyncIterator[str]:
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


@pytest_asyncio.fixture
async def app_client(rsa_keypair, postgres_url) -> AsyncIterator[AsyncClient]:
    priv, pub = rsa_keypair
    os.environ["DATABASE_URL"] = postgres_url
    os.environ["JWT_PRIVATE_KEY_PATH"] = str(priv)
    os.environ["JWT_PUBLIC_KEY_PATH"] = str(pub)
    os.environ["JWT_KID"] = "test-key"
    os.environ["JWT_ISSUER"] = "auth-service"
    os.environ["JWT_TTL_SECONDS"] = "60"

    # Re-import to pick up env vars
    from auth_service.config import get_settings  # noqa: PLC0415

    get_settings.cache_clear()

    from auth_service.db import engine  # noqa: PLC0415
    from auth_service.models.base import Base  # noqa: PLC0415
    from auth_service.models import user as _user_model  # noqa: F401, PLC0415

    # ensure pgcrypto for gen_random_uuid()
    async with engine.begin() as conn:
        await conn.exec_driver_sql('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        await conn.run_sync(Base.metadata.create_all)

    from auth_service.main import app  # noqa: PLC0415

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield client

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

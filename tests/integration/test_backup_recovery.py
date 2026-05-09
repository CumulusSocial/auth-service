"""Backup / recovery test.

Confirms that a `pg_dump` taken against the running database can be restored
into a freshly-dropped schema and a known row survives the round-trip.

Skipped locally if `pg_dump` / `pg_restore` aren't on PATH. CI installs
`postgresql-client` as part of the workflow so the test always runs there.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest

_PG_TOOLS_AVAILABLE = (
    shutil.which("pg_dump") is not None and shutil.which("pg_restore") is not None
)


def _libpq_url(asyncpg_url: str) -> str:
    """asyncpg URL → libpq URL (what pg_dump understands)."""
    return asyncpg_url.replace("postgresql+asyncpg://", "postgresql://")


@pytest.mark.skipif(not _PG_TOOLS_AVAILABLE, reason="pg_dump / pg_restore not installed")
@pytest.mark.asyncio
async def test_pg_dump_then_restore_round_trip(app_client, postgres_url, tmp_path):
    # 1. Insert a known row by registering a user.
    email = f"recover-{uuid.uuid4()}@example.com"
    r = await app_client.post(
        "/register",
        json={"email": email, "password": "hunter2hunter2", "display_name": "R"},
    )
    assert r.status_code == 201

    # 2. Dump.
    libpq = _libpq_url(postgres_url)
    dump = tmp_path / "backup.dump"
    subprocess.run(  # noqa: ASYNC221 — pg_dump is a one-shot subprocess; blocking is fine in this test
        ["pg_dump", "--format=custom", "--no-owner", "--dbname", libpq,
         "--file", str(dump)],
        check=True,
    )
    assert dump.exists() and dump.stat().st_size > 0

    # 3. Drop the schema.
    from auth_service.db import engine  # noqa: PLC0415
    async with engine.begin() as conn:
        await conn.exec_driver_sql("DROP SCHEMA public CASCADE")
        await conn.exec_driver_sql("CREATE SCHEMA public")
        await conn.exec_driver_sql('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # 4. Restore.
    subprocess.run(  # noqa: ASYNC221 — pg_restore is a one-shot subprocess; blocking is fine in this test
        ["pg_restore", "--no-owner", "--dbname", libpq, str(dump)],
        check=True,
    )

    # 5. Verify the row is back: log in with the same credentials.
    r = await app_client.post(
        "/login", json={"email": email, "password": "hunter2hunter2"}
    )
    assert r.status_code == 200

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_register_login_validate_jwks(app_client) -> None:
    # register
    r = await app_client.post(
        "/register",
        json={"email": "alice@example.com", "password": "hunter2hunter2", "display_name": "Alice"},
    )
    assert r.status_code == 201, r.text
    user_id = r.json()["user_id"]

    # duplicate registration -> 409
    r = await app_client.post(
        "/register",
        json={"email": "alice@example.com", "password": "hunter2hunter2", "display_name": "Alice"},
    )
    assert r.status_code == 409

    # login -> token
    r = await app_client.post(
        "/login", json={"email": "alice@example.com", "password": "hunter2hunter2"}
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    assert r.json()["expires_in"] > 0

    # bad password -> 401
    r = await app_client.post(
        "/login", json={"email": "alice@example.com", "password": "wrongwrongwrong"}
    )
    assert r.status_code == 401

    # validate
    r = await app_client.get("/validate", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["user_id"] == user_id

    # validate without token -> 403/401 (HTTPBearer auto_error -> 403)
    r = await app_client.get("/validate")
    assert r.status_code in (401, 403)

    # JWKS shape
    r = await app_client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.json()
    assert len(body["keys"]) == 1
    k = body["keys"][0]
    assert k["kty"] == "RSA" and k["alg"] == "RS256" and k["use"] == "sig"

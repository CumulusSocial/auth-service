from __future__ import annotations

import hmac
from typing import Annotated, Literal

from fastapi import APIRouter, Form, HTTPException, Request, status
from pydantic import BaseModel

from auth_service.config import settings
from auth_service.security.jwt import Keys, issue_service_token

router = APIRouter()


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    scope: Literal["service"] = "service"


@router.post("/oauth/token", response_model=TokenResponse)
async def token(
    request: Request,
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
) -> TokenResponse:
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported_grant_type",
        )
    expected = settings.service_clients.get(client_id)
    if expected is None or not hmac.compare_digest(expected, client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_client",
        )
    keys: Keys = request.app.state.jwt_keys
    access_token, ttl = issue_service_token(client_id=client_id, keys=keys)
    return TokenResponse(access_token=access_token, expires_in=ttl)

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth_service.security.jwt import Keys, verify_token

bearer = HTTPBearer(auto_error=True)


def get_keys(request: Request) -> Keys:
    return request.app.state.jwt_keys


def get_current_user_id(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    keys: Annotated[Keys, Depends(get_keys)],
) -> tuple[uuid.UUID, str]:
    try:
        claims = verify_token(credentials.credentials, keys)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)
        ) from e
    return uuid.UUID(claims["sub"]), claims["email"]

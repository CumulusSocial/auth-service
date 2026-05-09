from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db import get_session
from auth_service.deps import get_current_user_id, get_keys
from auth_service.schemas.auth import (
    JWKS,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    UserPublic,
    ValidateResponse,
)
from auth_service.security.jwt import Keys, issue_token
from auth_service.services.users import (
    EmailAlreadyRegistered,
    InvalidCredentials,
    authenticate,
    get_by_display_name,
    get_by_id,
    register_user,
)

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RegisterResponse:
    try:
        user_id = await register_user(
            session,
            email=str(body.email),
            password=body.password,
            display_name=body.display_name,
        )
    except EmailAlreadyRegistered as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="email already registered"
        ) from e
    return RegisterResponse(user_id=user_id)


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    keys: Annotated[Keys, Depends(get_keys)],
) -> LoginResponse:
    try:
        user = await authenticate(session, email=str(body.email), password=body.password)
    except InvalidCredentials as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        ) from e
    token, ttl = issue_token(user_id=user.id, email=user.email, keys=keys)
    return LoginResponse(access_token=token, expires_in=ttl)


@router.get("/validate", response_model=ValidateResponse)
async def validate(
    user: Annotated[tuple, Depends(get_current_user_id)],
) -> ValidateResponse:
    user_id, email = user
    return ValidateResponse(user_id=user_id, email=email)


@router.get("/users/{user_id}", response_model=UserPublic)
async def get_user(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> UserPublic:
    user = await get_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return UserPublic(user_id=user.id, display_name=user.display_name)


@router.get("/users/by-name/{display_name}", response_model=UserPublic)
async def get_user_by_name(
    display_name: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> UserPublic:
    user = await get_by_display_name(session, display_name)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return UserPublic(user_id=user.id, display_name=user.display_name)


@router.get("/.well-known/jwks.json", response_model=JWKS)
async def jwks(request: Request) -> JWKS:
    keys: Keys = request.app.state.jwt_keys
    return JWKS(keys=[keys.public_jwk])

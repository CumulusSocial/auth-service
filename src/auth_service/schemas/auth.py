from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=80)


class RegisterResponse(BaseModel):
    user_id: uuid.UUID


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class ValidateResponse(BaseModel):
    user_id: uuid.UUID
    email: EmailStr


class UserPublic(BaseModel):
    user_id: uuid.UUID
    display_name: str


class JWK(BaseModel):
    kty: str
    use: str
    alg: str
    kid: str
    n: str
    e: str


class JWKS(BaseModel):
    keys: list[JWK]

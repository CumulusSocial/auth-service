from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.models.user import User
from auth_service.security.passwords import hash_password, verify_password


class EmailAlreadyRegistered(Exception):
    pass


class InvalidCredentials(Exception):
    pass


async def register_user(
    session: AsyncSession, *, email: str, password: str, display_name: str
) -> uuid.UUID:
    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise EmailAlreadyRegistered(email)
    user = User(
        email=email,
        password_hash=hash_password(password),
        display_name=display_name,
    )
    session.add(user)
    await session.flush()
    return user.id


async def authenticate(
    session: AsyncSession, *, email: str, password: str
) -> User:
    user = await session.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.password_hash):
        raise InvalidCredentials()
    return user


async def get_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.scalar(select(User).where(User.id == user_id))


async def get_by_display_name(session: AsyncSession, display_name: str) -> User | None:
    return await session.scalar(
        select(User).where(User.display_name == display_name).order_by(User.created_at)
    )

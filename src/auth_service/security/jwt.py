from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jose import JWTError, jwt

from auth_service.config import settings


@dataclass(slots=True)
class Keys:
    private_pem: str
    public_pem: str
    public_jwk: dict


def _b64url_uint(n: int) -> str:
    byte_len = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).rstrip(b"=").decode("ascii")


def _public_to_jwk(public_pem: str, kid: str) -> dict:
    pub: RSAPublicKey = serialization.load_pem_public_key(public_pem.encode())  # type: ignore[assignment]
    nums = pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }


def load_keys() -> Keys:
    private_pem = Path(settings.jwt_private_key_path).read_text()
    public_pem = Path(settings.jwt_public_key_path).read_text()
    return Keys(
        private_pem=private_pem,
        public_pem=public_pem,
        public_jwk=_public_to_jwk(public_pem, settings.jwt_kid),
    )


SERVICE_NAMESPACE_UUID = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def service_subject(client_id: str) -> uuid.UUID:
    """Stable UUID for a service client_id, so downstream `sub` parses as UUID."""
    return uuid.uuid5(SERVICE_NAMESPACE_UUID, f"service:{client_id}")


def issue_service_token(*, client_id: str, keys: Keys) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.service_token_ttl_seconds
    payload = {
        "sub": str(service_subject(client_id)),
        "client_id": client_id,
        "scope": "service",
        "iat": now,
        "exp": exp,
        "iss": settings.jwt_issuer,
    }
    token = jwt.encode(
        payload,
        keys.private_pem,
        algorithm="RS256",
        headers={"kid": settings.jwt_kid},
    )
    return token, settings.service_token_ttl_seconds


def issue_token(*, user_id: uuid.UUID, email: str, keys: Keys) -> tuple[str, int]:
    now = int(time.time())
    exp = now + settings.jwt_ttl_seconds
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": exp,
        "iss": settings.jwt_issuer,
    }
    token = jwt.encode(
        payload,
        keys.private_pem,
        algorithm="RS256",
        headers={"kid": settings.jwt_kid},
    )
    return token, settings.jwt_ttl_seconds


def verify_token(token: str, keys: Keys) -> dict:
    try:
        return jwt.decode(
            token,
            keys.public_pem,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except JWTError as e:
        raise ValueError(f"invalid token: {e}") from e

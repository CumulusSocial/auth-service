from auth_service.security.passwords import hash_password, verify_password


def test_hash_and_verify_roundtrip() -> None:
    h = hash_password("hunter2hunter2")
    assert verify_password("hunter2hunter2", h)
    assert not verify_password("nope", h)

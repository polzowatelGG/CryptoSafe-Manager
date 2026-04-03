from core.crypto.key_derivation import KeyDerivation

def test_password_verification():
    kd = KeyDerivation({})
    h = kd.create_auth_hash("password")

    assert kd.verify_password("password", h)
    assert not kd.verify_password("wrong", h)
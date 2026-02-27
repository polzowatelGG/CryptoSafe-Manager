from core.crypto.placeholder import AES256Placeholder


def test_placeholder_encrypt_decrypt():
    p = AES256Placeholder()
    key = b"\x01\x02"
    data = b"hello"

    enc = p.encrypt(data, key)
    assert isinstance(enc, bytes)
    assert enc != data

    dec = p.decrypt(enc, key)
    assert dec == data

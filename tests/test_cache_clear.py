from core.crypto.key_cache import KeyCache

def test_cache_clear():
    cache = KeyCache()
    cache.store_key(b"secret")

    cache.clear_key()

    assert cache.get_key() is None
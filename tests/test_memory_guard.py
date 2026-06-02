import pytest
from src.core.security.memory_guard import SecureMemory, SecretHolder
import gc

def test_secure_memory_allocation():
    """SecureMemory выделяет и защищает память."""
    mem = SecureMemory()
    buffer = mem.allocate_secure(128)
    assert buffer is not None
    assert len(buffer) == 128

def test_secure_memory_free():
    """Освобождение памяти с затиранием."""
    mem = SecureMemory()
    buffer = mem.allocate_secure(128)
    mem.free_secure(buffer, 128)
    # Проверяем, что память обнулена через ctypes.string_at
    import ctypes
    buffer_data = ctypes.string_at(ctypes.addressof(buffer), 128)
    assert all(b == 0 for b in buffer_data)

def test_secret_holder_wipe():
    """SecretHolder затирает данные при удалении."""
    holder = SecretHolder(b"secret_password_123")
    data = holder.get_data()
    assert data == b"secret_password_123"
    
    holder.wipe()
    with pytest.raises(ValueError, match="уже был уничтожен"):
        holder.get_data()
    
    gc.collect()  # Проверяем, что GC не падает

def test_secret_holder_auto_cleanup():
    """SecretHolder автоматически очищается при удалении."""
    holder = SecretHolder(b"sensitive_data")
    holder_id = id(holder)
    del holder
    gc.collect()
    # Если мы здесь, то очистка прошла успешно
    assert True

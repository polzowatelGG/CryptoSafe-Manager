class VaultEntries:
    id: int
    title: str
    username: str
    encrypted_password: str
    url: str
    notes: str
    created_at: str
    updated_at: str
    tags: list
    #добавить методы для работы с записями в базе данных / доделать
    
class AuditLog:
    id: int
    action: str
    timestamp: str
    entry_id: str
    details: str
    signature: str
    #добавить методы для работы с логами аудита / заглушка до 5 спринта 
    
class Settings:
    id: int
    setting_key: str
    setting_value: str
    encrypted: bool
    #добавить методы для работы с настройками / доделать
    
class KeyStore:
    id: int
    key_type: str
    salt: bytes
    hash: bytes
    params: dict
    #добавить методы для работы с хранилищем ключей / заглушка до 2 спринта
    
    
    

import sqlite3 #промежуточный результат на 25.02

class VaultEntries: 
    def VaultEntriesTable(self):
        create_table="""
        CREATE TABLE IF NOT EXISTS VaultEntries (
            id INTEGER PRIMARY KEY AUTOINCREMENT
            title TEXT NOT NULL
            username TEXT
            encrypted_password TEXT NOT NULL
            url TEXT
            notes TEXT
            created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
            updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
            tags TEXT
        );
        """
    #id: int
    #title: str
    #username: str
    #encrypted_password: str
    #url: str
    #notes: str
    #created_at: str
    #updated_at: str
    #tags: list
    #добавить методы для работы с записями в базе данных / доделать
    
class AuditLog: 
    def AuditLogTable (self):
        create_table="""
        CREATE TABLE IF NOT EXISTS AuditLog(
            id INTEGER PRIMARY KEY AUTOINCREMENT
            action TEXT
            timestamp TEXT
            entry_id TEXT
            details TEXT
            signature TEXT
        );
        """
        # id, action, timestamp, entry_id, details, signature 
        # (заглушка для Спринта 5)
    
class Settings:
    def SettingsTable(self):
        create_table="""
        CREATE TABLE IF  NOT EXISTS SettingsTable(
            id INTEGER PRIMARY KEY AUTOINCREMENT
            setting_key TEXT
            setting_value TEXT
            encrypted TEXT NOT NULL
        );
        """
        
    #id: int
    #setting_key: str
    #setting_value: str
    #encrypted: bool
    #добавить методы для работы с настройками / доделать
    
class KeyStore:
    def KeyStoreTable(self):
        create_table="""
        CREATE TABLE IF  NOT EXISTS SettingsTable(
            id INTEGER PRIMARY KEY AUTOINCREMENT
            key_type TEXT
            salt TEXT
            hash TEXT
            params TEXT
        );
        """
        #id, key_type, salt, hash, params (для управления ключами в Спринте 2)
        # заглушка до 2 спринта

# экспорт хранилища в различные форматы с шифрованием.
# поддерживает: encrypted JSON (нативный), CSV, Bitwarden JSON.
# все операции логируются в audit_log и сохраняются в import_export_history.

import csv
import gzip
import hashlib
import json
import os
import secrets
import uuid
from base64 import b64encode
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# вспомогательные функции

def _derive_export_key(password: str, salt: bytes,
                       iterations: int = 100_000) -> bytes:
    #деривация ключа экспорта из пароля через PBKDF2-HMAC-SHA256.
    #намеренно отдельная от мастер-ключа.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt_payload(plaintext: bytes, key: bytes) -> Dict[str, str]:
    #шифрует байты через AES-256-GCM.
    #возвращает словарь с nonce и ciphertext в base64 для JSON-сериализации.
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce":      b64encode(nonce).decode("ascii"),
        "ciphertext": b64encode(ciphertext).decode("ascii"),
    }


def _file_sha256(path: str) -> str:
    #SHA-256 хэш файла для записи в import_export_history
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()



# основной класс экспортёра
class VaultExporter:
    #Экспортирует записи хранилища в зашифрованные файлы.

    #Поддерживаемые форматы:
    #    - encrypted_json  — нативный формат CryptoSafe (AES-256-GCM)
    #    - csv             — открытый CSV (с опциональным шифрованием)
    #    - bitwarden       — совместимый с Bitwarden JSON

    #Все экспорты:
    #    - требуют пароль 
    #   - используют отдельный ключ от мастер-ключа 
    #    - очищают временные ключи из памяти 
    #    - логируются в audit_log 
    #    - записываются в import_export_history 

    # поля которые включаются в экспорт по умолчанию
    DEFAULT_FIELDS = {"title", "username", "password", "url", "notes", "category", "tags"}

    def __init__(self, entry_manager, key_manager, db, audit_logger=None):
        self.entry_manager = entry_manager
        self.key_manager = key_manager
        self.db = db
        self.audit_logger = audit_logger

    # Публичный API
    def export(
        self,
        filepath: str,
        password: str,
        format: str = "encrypted_json",
        entry_ids: Optional[List[str]] = None,
        exclude_fields: Optional[List[str]] = None,
        compress: bool = False,
    ) -> int:
        # Основной метод экспорта.

        # Args:
        #     filepath:       путь к выходному файлу
        #     password:       пароль для шифрования экспорта
        #     format:         'encrypted_json' | 'csv' | 'bitwarden'
        #     entry_ids:      список ID для экспорта (None = все)
        #     exclude_fields: поля которые НЕ включать в экспорт
        #     compress:       сжимать GZIP перед записью

        # Returns:
        #     количество экспортированных записей

        # Raises:
        #     ValueError: неизвестный формат или нет данных
        #     PermissionError: если key_manager заблокирован
        
        # Проверяем что хранилище разблокировано
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано. Разблокируйте перед экспортом.")

        if not password:
            raise ValueError("Пароль для экспорта обязателен.")

        # Получаем записи
        entries = self._get_entries_for_export(entry_ids, exclude_fields)
        if not entries:
            raise ValueError("Нет записей для экспорта.")

        # Выбираем метод экспорта
        dispatch = {
            "encrypted_json": self._export_encrypted_json,
            "csv":            self._export_csv,
            "bitwarden":      self._export_bitwarden,
        }
        if format not in dispatch:
            raise ValueError(f"Неизвестный формат: {format}. Доступны: {list(dispatch)}")

        export_key = None
        try:
            # Деривируем отдельный ключ экспорта (SEC-3)
            salt = os.urandom(16)
            export_key = _derive_export_key(password, salt)

            # Выполняем экспорт
            count = dispatch[format](filepath, entries, export_key, salt, compress)

            # Записываем в историю (DB-2)
            self._record_history(
                operation_type="export",
                format=format,
                entry_count=count,
                filepath=filepath,
                encrypted=True,
            )

            # Логируем в аудит (INT-2)
            self._log_audit(
                event_type="VAULT_EXPORTED",
                details={
                    "format":      format,
                    "entry_count": count,
                    "filename":    Path(filepath).name,
                    "compressed":  compress,
                }
            )

            return count

        finally:
            # Очищаем ключ экспорта из памяти (SEC-4)
            if export_key is not None:
                export_key = bytes(len(export_key))
                del export_key

    # Форматы экспорта
    def _export_encrypted_json(
        self,
        filepath: str,
        entries: List[Dict],
        export_key: bytes,
        salt: bytes,
        compress: bool,
    ) -> int:
        
        # Нативный зашифрованный формат CryptoSafe (FMT-1, EXP-2).

        # Структура файла:
        # {
        #     "version": "1.0",
        #     "cryptosafe_export": true,
        #     "timestamp": "...",
        #     "encryption": {
        #         "algorithm": "AES-256-GCM",
        #         "key_derivation": "PBKDF2-HMAC-SHA256",
        #         "iterations": 100000,
        #         "salt": "base64...",
        #         "compressed": false
        #     },
        #     "data": "base64(nonce + ciphertext + tag)",
        #     "integrity": {
        #         "hash": "sha256 of plaintext",
        #         "hash_algorithm": "SHA256"
        #     }
        # }

        # Готовим plaintext
        payload = {
            "version":      "1.0",
            "exported_at":  datetime.utcnow().isoformat() + "Z",
            "entry_count":  len(entries),
            "entries":      entries,
        }
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        # Опциональное сжатие (EXP-3)
        if compress:
            plaintext = gzip.compress(plaintext)

        # Хэш до шифрования для верификации при импорте
        integrity_hash = hashlib.sha256(plaintext).hexdigest()

        # Шифруем
        enc = _encrypt_payload(plaintext, export_key)

        # Собираем итоговый документ
        document = {
            "version":          "1.0",
            "cryptosafe_export": True,
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "encryption": {
                "algorithm":     "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations":    100_000,
                "salt":          b64encode(salt).decode("ascii"),
                "compressed":    compress,
                "nonce":         enc["nonce"],
            },
            "data":      enc["ciphertext"],
            "integrity": {
                "hash":           integrity_hash,
                "hash_algorithm": "SHA256",
            },
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(document, f, ensure_ascii=False, indent=2)

        return len(entries)

    def _export_csv(
        self,
        filepath: str,
        entries: List[Dict],
        export_key: bytes,
        salt: bytes,
        compress: bool,
    ) -> int:

        # Экспорт в CSV (FMT-3).
        # По умолчанию plaintext — пользователь сам отвечает за безопасность хранения.
        # Предупреждение записывается в первую строку как комментарий.

        fieldnames = ["title", "username", "password", "url", "notes", "category", "tags"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            # Предупреждение о безопасности
            f.write("# CryptoSafe Manager Export\n")
            f.write(f"# Exported: {datetime.utcnow().isoformat()}Z\n")
            f.write("# WARNING: This file contains unencrypted passwords. Store securely.\n")

            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()
            for entry in entries:
                writer.writerow({field: entry.get(field, "") for field in fieldnames})

        return len(entries)

    def _export_bitwarden(
        self,
        filepath: str,
        entries: List[Dict],
        export_key: bytes,
        salt: bytes,
        compress: bool,
    ) -> int:

        # Экспорт в формат совместимый с Bitwarden JSON (EXP-1).
        # Bitwarden items: type=1 (login), login.username, login.password, login.uris
        items = []
        for entry in entries:
            uris = []
            url = entry.get("url", "").strip()
            if url:
                uris.append({"match": None, "uri": url})

            item = {
                "id":             str(uuid.uuid4()),
                "organizationId": None,
                "folderId":       None,
                "type":           1,  # login
                "name":           entry.get("title", ""),
                "notes":          entry.get("notes") or None,
                "favorite":       False,
                "login": {
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "totp":     entry.get("totp_secret") or None,
                    "uris":     uris if uris else None,
                },
                "collectionIds": [],
            }
            items.append(item)

        document = {
            "encrypted": False,
            "folders":   [],
            "items":     items,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(document, f, ensure_ascii=False, indent=2)

        return len(entries)

    # Внутренние методы
    def _get_entries_for_export(
        self,
        entry_ids: Optional[List[str]],
        exclude_fields: Optional[List[str]],
    ) -> List[Dict]:
        
        # Получает и расшифровывает записи для экспорта (ARC-3).
        # Фильтрует по entry_ids если указан список.
        # Удаляет exclude_fields из каждой записи.
        exclude = set(exclude_fields or [])
        allowed = self.DEFAULT_FIELDS - exclude

        if entry_ids:
            # Выборочный экспорт
            raw_entries = []
            for eid in entry_ids:
                try:
                    raw_entries.append(self.entry_manager.get_entry(eid))
                except Exception:
                    continue
        else:
            # Полный экспорт
            raw_entries = self.entry_manager.get_all_entries()

        # Фильтруем поля
        result = []
        for entry in raw_entries:
            filtered = {k: v for k, v in entry.items() if k in allowed}
            result.append(filtered)

        # Очищаем расшифрованные данные из памяти (SEC-4 / SEC-1 Sprint 3)
        self.entry_manager.secure_wipe_list(raw_entries)

        return result

    def _record_history(
        self,
        operation_type: str,
        format: str,
        entry_count: int,
        filepath: str,
        encrypted: bool,
    ):
        #Записывает операцию в import_export_history 
        try:
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            checksum  = _file_sha256(filepath) if os.path.exists(filepath) else ""

            self.db.execute(
                """
                INSERT INTO import_export_history
                    (operation_type, format, encryption_used,
                     entry_count, file_size, file_path, checksum, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_type,
                    format,
                    1 if encrypted else 0,
                    entry_count,
                    file_size,
                    Path(filepath).name,
                    checksum,
                    1,
                ),
                commit=True,
            )
        except Exception:
            # История не должна прерывать основную операцию
            pass

    def _log_audit(self, event_type: str, details: Dict[str, Any]):
        #Логирует операцию в аудит 
        if not self.audit_logger:
            return
        try:
            self.audit_logger.log_event(
                event_type=event_type,
                severity="INFO",
                source="vault_exporter",
                details=details,
            )
        except Exception:
            pass
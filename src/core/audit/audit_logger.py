# Простая реализация аудита событий в приложении. Логирует важные действия пользователя и системные события.
# Каждая запись содержит:
# - timestamp: время события
# - event_type: тип события (например, LOGIN_SUCCESS, ENTRY_CREATED)
# - severity: уровень важности (INFO, WARN, ERROR)
# - source: источник события (authentication, entry_manager)
# - user_id: идентификатор пользователя (если применимо)
# - details: словарь с дополнительными данными (например, entry_id)
# - sequence_number: порядковый номер записи для обеспечения целостности
# - previous_hash: хеш предыдущей записи для создания цепочки
# - entry_hash: хеш текущей записи для проверки целостности
# - signature: цифровая подпись записи для защиты от подделки

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional


class AuditLogger: # основной класс для логирования событий аудита
    def __init__(self, db, signer, event_bus):
        self.db = db
        self.signer = signer
        self._subscribe(event_bus)
        self._ensure_genesis()

    def _subscribe(self, event_bus): # подписываемся на события из разных частей приложения
        events = {
            # аутентификация
            "UserLoggedIn":    lambda **kw: self._on_auth("LOGIN_SUCCESS", kw),
            "UserLoggedOut":   lambda **kw: self._on_auth("LOGOUT", kw),
            "LoginFailed":     lambda **kw: self._on_auth("LOGIN_FAILED", kw),
            # vault операции
            "EntryCreated":    lambda **kw: self._on_vault("ENTRY_CREATED", kw),
            "EntryUpdated":    lambda **kw: self._on_vault("ENTRY_UPDATED", kw),
            "EntryDeleted":    lambda **kw: self._on_vault("ENTRY_DELETED", kw),
            # буфер обмена
            "ClipboardCopied": lambda **kw: self._on_clipboard("CLIPBOARD_COPIED", kw),
            "ClipboardCleared":lambda **kw: self._on_clipboard("CLIPBOARD_CLEARED", kw),
        }
        for event_name, handler in events.items():
            event_bus.subscribe(event_name, handler)

    # обработчики событий 

    def _on_auth(self, event_type: str, kw: dict): # для событий аутентификации логируем тип события и user_id, а также помечаем неудачные попытки как WARN
        severity = "WARN" if event_type == "LOGIN_FAILED" else "INFO"
        self.log_event(
            event_type=event_type,
            severity=severity,
            source="authentication",
            details={"user_id": kw.get("user_id", "master")},
        )

    def _on_vault(self, event_type: str, kw: dict): # для операций с записями логируем тип события и id записи, но не само содержимое 
        self.log_event(
            event_type=event_type,
            severity="INFO",
            source="entry_manager",
            # entry_id логируем, но не сам пароль — SEC требование
            details={"entry_id": kw.get("entry_id")},
        )

    def _on_clipboard(self, event_type: str, kw: dict): # для событий буфера обмена логируем тип события и id записи, откуда скопировано, но не само содержимое 
        self.log_event(
            event_type=event_type,
            severity="INFO",
            source="clipboard_service",
            details={
                "data_type": kw.get("data_type"),
                "entry_id": kw.get("source_entry_id"),
                # само содержимое буфера НИКОГДА не логируем
            },
        )

    # публичный API 

    def log_event(self, event_type: str, severity: str, source: str,details: Dict[str, Any], user_id: Optional[str] = None):
        # базовая валидация входных данных для обеспечения консистентности логов
        if not event_type or not severity or not source:
            raise ValueError("event_type, severity и source обязательны")

        entry = {
            "timestamp":       datetime.utcnow().isoformat() + "Z",
            "event_type":      event_type,
            "severity":        severity,
            "user_id":         user_id or "master",
            "source":          source,
            "details":         self._sanitize_details(details),
            "sequence_number": self._get_next_sequence(),
            "previous_hash":   self._get_last_hash(),
        }

        self._write_entry(entry)


    def _ensure_genesis(self):
        # проверяем, есть ли уже записи в логе. если нет, создаем "генезис" - первую запись, которая не имеет предыдущей и служит началом цепочки
        row = self.db.execute(
            "SELECT COUNT(*) as cnt FROM audit_log"
        ).fetchone()

        if row["cnt"] == 0:
            genesis = {
                "timestamp":       datetime.utcnow().isoformat() + "Z",
                "event_type":      "SYSTEM_GENESIS",
                "severity":        "INFO",
                "user_id":         "system",
                "source":          "audit_logger",
                "details":         {"message": "Audit log initialized"},
                "sequence_number": 0,
                "previous_hash":   "0" * 64,
            }
            self._write_entry(genesis)

    def _get_next_sequence(self) -> int: # получаем максимальный sequence_number из базы данных и возвращаем следующий. если записей нет, начинаем с 0.
        row = self.db.execute(
            "SELECT MAX(sequence_number) as max_seq FROM audit_log"
        ).fetchone()
        current = row["max_seq"]
        return (current + 1) if current is not None else 0

    def _get_last_hash(self) -> str: # получаем entry_hash последней записи для обеспечения целостности цепочки. если записей нет, возвращаем строку из 64 нулей.
        row = self.db.execute(
            "SELECT entry_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else "0" * 64

    def _write_entry(self, entry: Dict[str, Any]): # сериализуем запись в JSON, вычисляем ее хеш и создаем цифровую подпись, затем сохраняем все это в базе данных
        entry_json = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        signature  = self.signer.sign(entry_json.encode())

        self.db.execute( 
            """
            INSERT INTO audit_log
                (sequence_number, previous_hash, entry_data, entry_hash, signature, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry["sequence_number"],
                entry["previous_hash"],
                entry_json,
                entry_hash,
                signature.hex(),
                entry["timestamp"],
            ),
            commit=True,  
        )

    def _sanitize_details(self, details: dict) -> dict: # функция для удаления или маскировки чувствительных данных в details, таких как пароли, ключи и т.д.
        FORBIDDEN = {"password", "key", "secret", "token", "hash", "pin"}
        clean = {}
        for k, v in details.items():
            if any(f in k.lower() for f in FORBIDDEN):
                clean[k] = "[REDACTED]"
            else:
                clean[k] = v
        return clean
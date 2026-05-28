# src/core/import_export/importer.py
# Импорт записей в хранилище из различных форматов.
# Поддерживает: encrypted JSON (нативный), CSV, Bitwarden JSON, LastPass CSV.
# Все операции логируются в audit_log и сохраняются в import_export_history.

import csv
import gzip
import hashlib
import io
import json
import os
import re
import threading
from base64 import b64decode
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging as _imp_log
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



# Константы
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024   # 10 МБ 
IMPORT_TIMEOUT_SECONDS = 30              # таймаут обработки 

# Обязательные поля записи — остальные получают значения по умолчанию
REQUIRED_FIELDS = {"title"}

# Максимальная длина строковых полей для санитизации (SEC-2)
FIELD_MAX_LEN = {
    "title":    200,
    "username": 500,
    "password": 1000,
    "url":      2000,
    "notes":    5000,
    "category": 100,
    "tags":     500,
}

# Паттерны для обнаружения вредоносного содержимого (SEC-5 Sprint 6)
_MALICIOUS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
    re.compile(r"vbscript:", re.IGNORECASE),
]
_CSV_FORMULA_RE = re.compile(r'^[=+\-@|]')


# Вспомогательные функции
def _derive_export_key(password: str, salt: bytes,
                       iterations: int = 100_000) -> bytes:
    #Деривация ключа из пароля — зеркало функции в exporter.py 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _sanitize_field(value: Any, field_name: str) -> str:

    # Санитизация одного поля записи (SEC-2, IMP-2):
    # - приводит к строке
    # - обрезает до максимальной длины
    # - удаляет управляющие символы
    # - проверяет на вредоносные паттерны
    if value is None:
        return ""
    text = str(value)

    # Удаляем управляющие символы кроме \n и \t
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Проверяем на вредоносные паттерны
    for pattern in _MALICIOUS_PATTERNS:
        if pattern.search(text):
            # Не бросаем исключение — просто удаляем опасный фрагмент
            text = pattern.sub("[REMOVED]", text)

    # Обрезаем до лимита
    if _CSV_FORMULA_RE.match(text):
        text = "'" + text  # апостроф — стандартная защита от formula injection
    max_len = FIELD_MAX_LEN.get(field_name, 1000)
    return text[:max_len]


def _sanitize_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
    # Санитизирует все поля записи
    return {
        "title":    _sanitize_field(raw.get("title"),    "title"),
        "username": _sanitize_field(raw.get("username"), "username"),
        "password": _sanitize_field(raw.get("password"), "password"),
        "url":      _sanitize_field(raw.get("url"),      "url"),
        "notes":    _sanitize_field(raw.get("notes"),    "notes"),
        "category": _sanitize_field(raw.get("category"), "category"),
        "tags":     _sanitize_field(raw.get("tags"),     "tags"),
    }


def _detect_format(filepath: str) -> str:
    # Автоматически определяет формат файла 
    # Порядок: по содержимому > по расширению.
    # Возвращает: 'encrypted_json' | 'bitwarden' | 'lastpass_csv' | 'csv
    path = Path(filepath)
    ext  = path.suffix.lower()

    # Читаем первые 4 КБ для определения формата
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(4096)
    except Exception:
        # Если не читается как текст — считаем бинарным/неизвестным
        return "unknown"

    # Нативный зашифрованный формат CryptoSafe
    if '"cryptosafe_export"' in head and '"true"' not in head:
        try:
            data = json.loads(head if len(head) < 4096 else open(filepath).read())
            if data.get("cryptosafe_export") is True:
                return "encrypted_json"
        except Exception:
            pass

    # Bitwarden JSON — содержит "items" и "encrypted": false/true
    if '"items"' in head and ('"login"' in head or '"encrypted"' in head):
        return "bitwarden"

    # LastPass CSV — первая строка содержит характерные заголовки
    first_line = head.split("\n")[0].lower()
    if "url,username,password,extra,name,grouping,fav" in first_line:
        return "lastpass_csv"

    # Обычный CSV
    if ext in (".csv",):
        return "csv"

    # JSON без признаков известных форматов
    if ext in (".json",):
        return "unknown"


def _entry_fingerprint(entry: Dict[str, Any]) -> str:
    # Создаёт отпечаток записи для дедупликации 
    # Используется title + username + url (нижний регистр).
    key = (
        (entry.get("title")    or "").lower().strip() + "|" +
        (entry.get("username") or "").lower().strip() + "|" +
        (entry.get("url")      or "").lower().strip()
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _entries_are_equal(existing: Dict[str, Any], incoming: Dict[str, Any]) -> bool:
    fields_to_compare = ["title", "username", "password", "url", "notes", "category", "tags"]
    for field in fields_to_compare:
        if (existing.get(field) or "") != (incoming.get(field) or ""):
            return False
    return True


# Результат импорта
class ImportResult:
    # Итог операции импорта — передаётся в UI для отображения

    def __init__(self):
        self.total_parsed:    int = 0   # всего прочитано из файла
        self.imported:        int = 0   # добавлено новых записей
        self.updated:         int = 0   # обновлено существующих (merge)
        self.skipped:         int = 0   # пропущено (дубликаты в replace/dry-run)
        self.errors:          List[str] = []
        self.dry_run_entries: List[Dict] = []  # для dry-run превью

    def __repr__(self) -> str:
        return (
            f"ImportResult(parsed={self.total_parsed}, "
            f"imported={self.imported}, updated={self.updated}, "
            f"skipped={self.skipped}, errors={len(self.errors)})"
        )



# Основной класс импортёра
class VaultImporter:
    # Импортирует записи в хранилище из файлов различных форматов.

    # Режимы 
    #     merge   — добавляет новые, обновляет существующие по отпечатку
    #     replace — очищает хранилище и импортирует всё заново
    #     dry_run — только парсит и возвращает превью, ничего не сохраняет

    # Безопасность:
    #     - лимит файла 10 МБ 
    #     - таймаут обработки 30 с 
    #     - санитизация всех полей 
    #     - проверка на вредоносные паттерны 
    #     - верификация шифрования перед дешифрованием 
    def __init__(self, entry_manager, key_manager, db, audit_logger=None):
        self.entry_manager = entry_manager
        self.key_manager   = key_manager
        self.db            = db
        self.audit_logger  = audit_logger

    # Публичный API
    def import_file(
        self,
        filepath: str,
        password: Optional[str] = None,
        format: Optional[str] = None,
        mode: str = "merge",
    ) -> ImportResult:
        # Основной метод импорта.

        # Args:
        #     filepath: путь к файлу
        #     password: пароль для расшифровки (для encrypted_json)
        #     format:   явное указание формата (None = авто-определение)
        #     mode:     'merge' | 'replace' | 'dry_run'

        # Returns:
        #     ImportResult с деталями операции

        # Raises:
        #     PermissionError: хранилище заблокировано
        #     ValueError:      неверный формат, файл слишком большой, таймаут
        #     FileNotFoundError: файл не найден
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")

        _imp_log.getLogger(__name__).warning(
            "IMP-01: Import running in main process without sandbox isolation. "
            "Only import files from trusted sources."
        )

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        # Проверяем размер файла (IMP-4)
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE_BYTES:
            raise ValueError(
                f"Файл слишком большой: {file_size // 1024 // 1024} МБ. "
                f"Максимум: {MAX_FILE_SIZE_BYTES // 1024 // 1024} МБ."
            )

        if mode not in ("merge", "replace", "dry_run"):
            raise ValueError(f"Неизвестный режим: {mode}. Доступны: merge, replace, dry_run")

        # Определяем формат
        detected_format = format or _detect_format(filepath)
        if detected_format == "unknown":
            raise ValueError(
                "Не удалось определить формат файла. "
                "Укажите формат явно через параметр format."
            )

        # Запускаем импорт с таймаутом (IMP-4)
        result_holder: List[Any] = [None, None]  # [result, exception]

        def _do_import():
            try:
                result_holder[0] = self._run_import(
                    filepath, password, detected_format, mode, file_size
                )
            except Exception as exc:
                result_holder[1] = exc

        thread = threading.Thread(target=_do_import, daemon=True)
        thread.start()
        thread.join(timeout=IMPORT_TIMEOUT_SECONDS)

        if thread.is_alive():
            raise ValueError(
                f"Импорт превысил таймаут {IMPORT_TIMEOUT_SECONDS} секунд. "
                "Файл может быть слишком большим или повреждённым."
            )

        if result_holder[1] is not None:
            raise result_holder[1]

        return result_holder[0]

    # Внутренняя логика импорта
    def _run_import(
        self,
        filepath: str,
        password: Optional[str],
        format: str,
        mode: str,
        file_size: int,
    ) -> ImportResult:
        # Выполняет фактический импорт в зависимости от формата

        # Парсим файл в список сырых записей
        parse_dispatch = {
            "encrypted_json": self._parse_encrypted_json,
            "bitwarden":      self._parse_bitwarden,
            "lastpass_csv":   self._parse_lastpass_csv,
            "csv":            self._parse_csv,
        }
        parser = parse_dispatch.get(format)
        if not parser:
            raise ValueError(f"Нет парсера для формата: {format}")

        raw_entries = parser(filepath, password)

        result = ImportResult()
        result.total_parsed = len(raw_entries)

        # Санитизируем все записи (SEC-2)
        clean_entries = []
        for i, raw in enumerate(raw_entries):
            try:
                clean = _sanitize_entry(raw)
                # Проверяем обязательные поля (IMP-2)
                if not clean.get("title"):
                    result.errors.append(f"Запись #{i+1}: пустое поле title — пропущена")
                    result.skipped += 1
                    continue
                clean_entries.append(clean)
            except Exception as e:
                result.errors.append(f"Запись #{i+1}: ошибка санитизации — {e}")
                result.skipped += 1

        # Dry-run: только возвращаем превью
        if mode == "dry_run":
            result.dry_run_entries = clean_entries
            result.imported = len(clean_entries)
            return result

        # Replace: очищаем хранилище перед импортом
        if mode == "replace":
            self._clear_vault()

        # Получаем отпечатки существующих записей для дедупликации (IMP-2)
        existing_fingerprints: Dict[str, str] = {}  # fingerprint → entry_id
        if mode == "merge":
            existing_fingerprints = self._get_existing_fingerprints()

        # Сохраняем записи
        for entry in clean_entries:
            try:
                fingerprint = _entry_fingerprint(entry)

                if mode == "merge" and fingerprint in existing_fingerprints:
                    existing_id = existing_fingerprints[fingerprint]
                    existing_entry = self.entry_manager.get_entry(existing_id)
                    if _entries_are_equal(existing_entry, entry):
                        result.skipped += 1
                        continue
                    self.entry_manager.update_entry(existing_id, entry)
                    result.updated += 1
                else:
                    self.entry_manager.create_entry(entry)
                    result.imported += 1

            except Exception as e:
                result.errors.append(
                    f"Ошибка сохранения '{entry.get('title', '?')}': {e}"
                )
                result.skipped += 1

        # Записываем в историю 
        self._record_history(
            operation_type="import",
            format=format,
            entry_count=result.imported + result.updated,
            filepath=filepath,
            file_size=file_size,
        )

        # Логируем в аудит 
        self._log_audit(
            event_type="VAULT_IMPORTED",
            details={
                "format":   format,
                "mode":     mode,
                "imported": result.imported,
                "updated":  result.updated,
                "skipped":  result.skipped,
                "errors":   len(result.errors),
                "filename": Path(filepath).name,
            }
        )

        return result

    # Парсеры форматов
    def _parse_encrypted_json(
        self, filepath: str, password: Optional[str]
    ) -> List[Dict]:
        # Парсит нативный зашифрованный формат CryptoSafe 
        # Верифицирует структуру ПЕРЕД попыткой расшифровки 
        if not password:
            raise ValueError(
                "Для импорта зашифрованного файла CryptoSafe необходим пароль."
            )

        with open(filepath, "r", encoding="utf-8") as f:
            document = json.load(f)

        # Верификация структуры 
        if not document.get("cryptosafe_export"):
            raise ValueError("Файл не является экспортом CryptoSafe.")

        enc_meta = document.get("encryption", {})
        required_enc_keys = {"algorithm", "key_derivation", "iterations", "salt", "nonce"}
        missing = required_enc_keys - set(enc_meta.keys())
        if missing:
            raise ValueError(f"Повреждённый файл: отсутствуют поля шифрования: {missing}")

        if enc_meta.get("algorithm") != "AES-256-GCM":
            raise ValueError(
                f"Неподдерживаемый алгоритм: {enc_meta.get('algorithm')}. "
                "Ожидается AES-256-GCM."
            )

        # Деривируем ключ
        export_key = None
        try:
            salt       = b64decode(enc_meta["salt"])
            nonce      = b64decode(enc_meta["nonce"])
            iterations = int(enc_meta.get("iterations", 100_000))
            ciphertext = b64decode(document["data"])

            export_key = _derive_export_key(password, salt, iterations)

            # Расшифровываем
            aesgcm    = AESGCM(export_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        except Exception as e:
            raise ValueError(
                f"Не удалось расшифровать файл. "
                f"Возможно, неверный пароль или повреждённый файл. ({e})"
            )
        finally:
            # Очищаем ключ из памяти 
            if export_key is not None:
                export_key = bytes(len(export_key))
                del export_key

        # Опциональная распаковка GZIP
        if enc_meta.get("compressed"):
            plaintext = gzip.decompress(plaintext)

        # Верификация целостности
        integrity = document.get("integrity", {})
        if integrity.get("hash"):
            computed = hashlib.sha256(plaintext).hexdigest()
            if computed != integrity["hash"]:
                raise ValueError(
                    "Нарушение целостности файла: хэш не совпадает. "
                    "Файл мог быть повреждён или изменён."
                )

        payload = json.loads(plaintext.decode("utf-8"))
        return payload.get("entries", [])

    def _parse_bitwarden(
        self, filepath: str, password: Optional[str]
    ) -> List[Dict]:
        # Парсит Bitwarden JSON export (
        # Поддерживает незашифрованный формат (encrypted: false).
        # Тип записи 1 = login.
        with open(filepath, "r", encoding="utf-8") as f:
            document = json.load(f)

        if document.get("encrypted"):
            raise ValueError(
                "Зашифрованный Bitwarden экспорт не поддерживается. "
                "Экспортируйте из Bitwarden без шифрования."
            )

        items = document.get("items", [])
        entries = []

        for item in items:
            # Обрабатываем только логины (type=1)
            if item.get("type") != 1:
                continue

            login = item.get("login", {})
            uris  = login.get("uris") or []
            url   = uris[0].get("uri", "") if uris else ""

            entries.append({
                "title":    item.get("name", ""),
                "username": login.get("username", ""),
                "password": login.get("password", ""),
                "url":      url,
                "notes":    item.get("notes", "") or "",
                "category": item.get("folderId", "") or "",
                "tags":     "",
            })

        return entries

    def _parse_lastpass_csv(
        self, filepath: str, password: Optional[str]
    ) -> List[Dict]:
        # Парсит LastPass CSV export 
        # Стандартный заголовок: url,username,password,extra,name,grouping,fav
        entries = []

        with open(filepath, "r", encoding="utf-8", newline="") as f:
            # Пропускаем строки-комментарии
            lines = [line for line in f if not line.startswith("#")]

        reader = csv.DictReader(io.StringIO("".join(lines)))

        for row in reader:
            # LastPass использует 'name' как заголовок, 'extra' как заметки
            # 'grouping' как категорию
            url = row.get("url", "").strip()
            # LastPass сохраняет имя сайта как 'name', адрес как 'url'
            # Если url == 'http://sn' — это secure note, пропускаем
            if url.lower() in ("http://sn", "https://sn"):
                continue

            entries.append({
                "title":    row.get("name", "").strip(),
                "username": row.get("username", "").strip(),
                "password": row.get("password", "").strip(),
                "url":      url,
                "notes":    row.get("extra", "").strip(),
                "category": row.get("grouping", "").strip(),
                "tags":     "",
            })

        return entries

    def _parse_csv(
        self, filepath: str, password: Optional[str]
    ) -> List[Dict]:
        # Парсит универсальный CSV 
        # Поддерживает заголовки: title, username, password, url, notes, category, tags.
        # Нечувствителен к регистру заголовков и порядку колонок.
        entries = []

        with open(filepath, "r", encoding="utf-8", newline="") as f:
            # Пропускаем строки-комментарии (начинаются с #)
            lines = [line for line in f if not line.startswith("#")]

        if not lines:
            return entries

        reader = csv.DictReader(io.StringIO("".join(lines)))

        # Нормализуем заголовки к нижнему регистру
        if reader.fieldnames:
            reader.fieldnames = [h.lower().strip() for h in reader.fieldnames]

        for row in reader:
            # Поддерживаем альтернативные имена колонок
            title = (
                row.get("title") or row.get("name") or
                row.get("site") or row.get("service") or ""
            ).strip()

            entries.append({
                "title":    title,
                "username": (row.get("username") or row.get("login") or row.get("email") or "").strip(),
                "password": (row.get("password") or row.get("pass") or "").strip(),
                "url":      (row.get("url") or row.get("website") or row.get("uri") or "").strip(),
                "notes":    (row.get("notes") or row.get("note") or row.get("comment") or "").strip(),
                "category": (row.get("category") or row.get("group") or row.get("folder") or "").strip(),
                "tags":     (row.get("tags") or row.get("tag") or "").strip(),
            })

        return entries

    # Вспомогательные методы
    def _get_existing_fingerprints(self) -> Dict[str, str]:
        # Получает отпечатки всех существующих записей для дедупликации.
        # Возвращает словарь fingerprint → entry_id.
        fingerprints: Dict[str, str] = {}
        try:
            all_entries = self.entry_manager.get_all_entries()
            for entry in all_entries:
                fp = _entry_fingerprint(entry)
                fingerprints[fp] = entry.get("id", "")
            # Очищаем расшифрованные данные (SEC-1 Sprint 3)
            self.entry_manager.secure_wipe_list(all_entries)
        except Exception:
            pass
        return fingerprints

    def _clear_vault(self):
        # Удаляет все записи из хранилища (для режима replace
        try:
            all_entries = self.entry_manager.get_all_entries()
            ids = [e.get("id") for e in all_entries if e.get("id")]
            self.entry_manager.secure_wipe_list(all_entries)
            for entry_id in ids:
                try:
                    self.entry_manager.delete_entry(entry_id, soft_delete=False)
                except Exception:
                    pass
        except Exception:
            pass

    def _record_history(
        self,
        operation_type: str,
        format: str,
        entry_count: int,
        filepath: str,
        file_size: int,
    ):
        # Записывает операцию в import_export_history 
        try:
            checksum = ""
            if os.path.exists(filepath):
                h = hashlib.sha256()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                checksum = h.hexdigest()

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
                    1 if format == "encrypted_json" else 0,
                    entry_count,
                    file_size,
                    Path(filepath).name,
                    checksum,
                    1,
                ),
                commit=True,
            )
        except Exception:
            pass

    def _log_audit(self, event_type: str, details: Dict[str, Any]):
        # Логирует операцию в аудит 
        if not self.audit_logger:
            return
        try:
            self.audit_logger.log_event(
                event_type=event_type,
                severity="INFO",
                source="vault_importer",
                details=details,
            )
        except Exception:
            pass
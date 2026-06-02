
import re
import base64
import gzip
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .crypto import checksum, decrypt_aes_gcm, decrypt_with_private_key, derive_password_key, wipe_bytes
from .exceptions import ImportValidationError
from .formats import BitwardenJSONFormat, CSVVaultFormat, LastPassCSVFormat, NativeJSONFormat
from .models import ImportOptions


@dataclass
class ImportResult:
    total_parsed: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    imported: int = 0
    mode: str = "dry-run"
    errors: List[str] = field(default_factory=list)
    dry_run_entries: List[Dict[str, Any]] = field(default_factory=list)


def _normalize_mode(mode: str) -> str:
    return str(mode or "dry-run").replace("_", "-").strip().lower()


def _detect_format(path: str) -> str:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        try:
            text = file_path.read_text(encoding="utf-8-sig")
        except Exception:
            return "csv"
        header = text.lstrip().splitlines()[0] if text else ""
        if header.lower().startswith("url,username,password"):
            return "lastpass_csv"
        return "csv"
    if suffix in {".json", ".txt"}:
        try:
            data = json.loads(file_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return "csv"
        if isinstance(data, dict):
            if data.get("cryptosafe_export"):
                return "encrypted_json"
            if data.get("encrypted") and data.get("passwordProtected"):
                return "bitwarden_encrypted"
            if isinstance(data.get("items"), list):
                return "bitwarden"
        return "csv"
    return "csv"


class VaultImporter:
    MALICIOUS_PATTERNS = (
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"<\s*iframe", re.IGNORECASE),
    )

    def __init__(self, entry_manager, key_manager=None, database=None, db=None, event_bus=None):
        self.entry_manager = entry_manager
        self.key_manager = key_manager
        self.database = database if database is not None else db
        self.event_bus = event_bus

    def import_file(
        self,
        filepath: str,
        password: str | None = None,
        format: str | None = None,
        mode: str = "dry_run",
        duplicate_strategy: str = "skip",
        max_file_size: int = 10 * 1024 * 1024,
        timeout_seconds: int = 30,
    ) -> Dict[str, Any]:
        if not filepath:
            raise ValueError("File path is required")
        fmt = format or "auto"
        if fmt == "auto":
            fmt = _detect_format(filepath)
        opts = ImportOptions(
            format=fmt,
            mode=_normalize_mode(mode),
            duplicate_strategy=duplicate_strategy,
            max_file_size=max_file_size,
            timeout_seconds=timeout_seconds,
        )
        payload = Path(filepath).read_bytes()
        if fmt == "encrypted_json":
            if not password:
                raise ValueError("Password required for encrypted_json import")
            return self.import_encrypted_json(payload, password, opts)
        if fmt in {"csv", "cryptosafe_csv", "lastpass", "lastpass_csv", "bitwarden", "bitwarden_json"}:
            return self.import_plaintext(payload, opts)
        if fmt == "bitwarden_encrypted":
            raise ImportValidationError("Encrypted Bitwarden import is not supported yet")
        raise ImportValidationError(f"Unsupported import format: {fmt}")

    def validate_entries(self, entries, options=None):
        _ = options or ImportOptions()
        validated = []
        for idx, entry in enumerate(entries, 1):
            normalized = self._sanitize_entry(entry)
            if not normalized["title"]:
                raise ImportValidationError(f"Entry #{idx} missing title")
            # Пароль необязателен — пропускаем пустые записи вместо падения
            validated.append(normalized)
        return validated

    def preview_encrypted_json(self, package_payload: str | bytes, password: str, options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        opts = options or ImportOptions(format="encrypted_json")
        package = self._load_native_package(package_payload, opts)
        plaintext = self._decrypt_native_payload(package, password)
        entries = self.validate_entries(plaintext.get("entries", []), opts)
        return entries

    def import_encrypted_json(self, package_payload: str | bytes, password: str, options: ImportOptions | None = None) -> Dict[str, Any]:
        start = time.monotonic()
        opts = options or ImportOptions(format="encrypted_json", mode="dry-run")
        entries = self.preview_encrypted_json(package_payload, password, opts)
        result = ImportResult(
            total_parsed=len(entries),
            created=0,
            updated=0,
            skipped=0,
            imported=0,
            mode=opts.mode,
            dry_run_entries=entries if opts.mode == "dry-run" else [],
        )
        if opts.mode == "dry-run":
            self._record_history(
                "import", "encrypted_json", "AES-GCM", len(entries),
                len(self._as_bytes(package_payload)), "dry-run", "validated", result.__dict__)
            return result

        if opts.mode == "replace":
            self._clear_vault()
        existing = {} if opts.mode == "replace" else self._existing_entries_by_identity()
        deadline = start + max(1, int(opts.timeout_seconds))
        for entry in entries:
            if time.monotonic() > deadline:
                raise ImportValidationError("Import timed out")
            ident = self._identity(entry)
            existing_entry = existing.get(ident)
            if existing_entry and opts.duplicate_strategy == "skip":
                result.skipped += 1
                continue
            if existing_entry and opts.duplicate_strategy == "replace":
                self.entry_manager.update_entry(existing_entry["id"], entry)
                result.updated += 1
                continue
            self.entry_manager.create_entry(entry)
            result.created += 1

        result.imported = result.created
        self._record_history(
            "import", "encrypted_json", "AES-GCM", len(entries),
            len(self._as_bytes(package_payload)), "applied", "verified", result.__dict__)
        return result

    def preview_plaintext(self, payload: str | bytes, options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        opts = options or ImportOptions(format="csv")
        raw_entries = self._parse_plaintext_payload(payload, opts)
        return self.validate_entries(raw_entries, opts)

    def import_plaintext(self, payload: str | bytes, options: ImportOptions | None = None) -> Dict[str, Any]:
        start = time.monotonic()
        opts = options or ImportOptions(format="csv", mode="dry-run")
        entries = self.preview_plaintext(payload, opts)
        result = self._apply_entries(entries, opts, start)
        self._record_history(
            "import", opts.format, "none", len(entries), len(self._as_bytes(payload)),
            checksum(self._as_bytes(payload)), "validated" if opts.mode == "dry-run" else "verified", result.__dict__ if isinstance(result, ImportResult) else result
        )
        return result

    def _sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, str]:
        return {
            "title": self._sanitize_text(entry.get("title", "")),
            "username": self._sanitize_text(entry.get("username", "")),
            "password": str(entry.get("password", "") or ""),
            "url": self._sanitize_text(entry.get("url", "")),
            "notes": self._sanitize_text(entry.get("notes", "")),
            "category": self._sanitize_text(entry.get("category", "")),
            "tags": self._sanitize_text(entry.get("tags", "")),
        }

    def _sanitize_text(self, value: Any) -> str:
        text = str(value or "").replace("\x00", "").strip()
        for pat in self.MALICIOUS_PATTERNS:
            if pat.search(text):
                raise ImportValidationError("Imported data contains blocked active content")
        return text

    def _load_native_package(self, package_payload: str | bytes, options: ImportOptions) -> Dict[str, Any]:
        payload_bytes = self._as_bytes(package_payload)
        if len(payload_bytes) > max(1, int(options.max_file_size)):
            raise ValueError("Import file exceeds max size")
        try:
            package = NativeJSONFormat().deserialize_header(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            raise ImportValidationError("Native export package is invalid JSON") from e
        NativeJSONFormat().validate_package(package)
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        if checksum(ciphertext) != str(package["integrity"].get("checksum", "")):
            raise ImportValidationError("Native export checksum mismatch")
        return package

    def _parse_plaintext_payload(self, payload: str | bytes, options: ImportOptions) -> List[Dict[str, str]]:
        payload_bytes = self._as_bytes(payload)
        if len(payload_bytes) > max(1, int(options.max_file_size)):
            raise ValueError("Import file exceeds max size")
        text = payload_bytes.decode("utf-8-sig")
        fmt = str(options.format or "csv").strip().lower()
        if fmt in {"csv", "cryptosafe_csv"}:
            return CSVVaultFormat().parse_rows(text)
        if fmt in {"lastpass", "lastpass_csv"}:
            return LastPassCSVFormat().parse_entries(text)
        if fmt in {"bitwarden", "bitwarden_json"}:
            return BitwardenJSONFormat().parse_entries(text)
        raise ImportValidationError(f"Unsupported import format: {options.format}")

    def _decrypt_native_payload(self, package: Dict[str, Any], password: str) -> Dict[str, Any]:
        enc = package["encryption"]
        if enc.get("method") == "public_key":
            plain = decrypt_with_private_key(
                {
                    "encrypted_key": package["data"].get("encrypted_key", ""),
                    "nonce": enc.get("nonce", ""),
                    "ciphertext": package["data"].get("ciphertext", ""),
                    "checksum": package["integrity"].get("checksum", ""),
                },
                password,
            )
            return self._decode_native_plaintext(package, plain)

        salt = self._decode_b64(enc.get("salt", ""))
        nonce = self._decode_b64(enc.get("nonce", ""))
        ciphertext = self._decode_b64(package["data"].get("ciphertext", ""))
        bits = 128 if "128" in enc.get("algorithm", "") else 256
        key = derive_password_key(password, salt, bits=bits, iterations=int(enc.get("iterations", 100000)))
        keybuf = bytearray(key)
        try:
            expected_hmac = str(package["integrity"].get("hmac", ""))
            if expected_hmac:
                computed = hmac.new(bytes(keybuf), ciphertext, "sha256").hexdigest()
                if not hmac.compare_digest(computed, expected_hmac):
                    raise ImportValidationError("Native export HMAC mismatch")
            plaintext = decrypt_aes_gcm(ciphertext, keybuf, nonce)
        finally:
            wipe_bytes(keybuf)
        return self._decode_native_plaintext(package, plaintext)

    def _decode_native_plaintext(self, package: Dict[str, Any], plaintext: bytes) -> Dict[str, Any]:
        if checksum(plaintext) != str(package["integrity"].get("payload_checksum", "")):
            raise ImportValidationError("Native export plaintext checksum mismatch")
        if package.get("metadata", {}).get("compressed"):
            plaintext = gzip.decompress(plaintext)
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise ImportValidationError("Native export decrypted payload invalid") from e
        if not isinstance(decoded, dict) or not isinstance(decoded.get("entries"), list):
            raise ImportValidationError("Native export payload does not contain entries")
        return decoded

    def _decode_b64(self, value: str) -> bytes:
        try:
            return base64.b64decode(str(value).encode("ascii"), validate=True)
        except Exception as e:
            raise ImportValidationError("Native export contains invalid base64 data") from e

    def _as_bytes(self, value: str | bytes) -> bytes:
        return value if isinstance(value, bytes) else str(value).encode("utf-8")

    def _existing_entries_by_identity(self) -> Dict[tuple, Dict[str, Any]]:
        if not hasattr(self.entry_manager, "get_all_entries"):
            return {}
        return {self._identity(e): e for e in self.entry_manager.get_all_entries()}

    def _identity(self, entry: Dict[str, Any]) -> tuple:
        return (entry.get("title", "").strip().lower(), entry.get("username", "").strip().lower())

    def _apply_entries(self, entries: List[Dict[str, Any]], opts: ImportOptions, start: float) -> ImportResult:
        result = ImportResult(
            total_parsed=len(entries),
            created=0,
            updated=0,
            skipped=0,
            imported=0,
            mode=opts.mode,
            dry_run_entries=entries if opts.mode == "dry-run" else [],
        )
        if opts.mode == "dry-run":
            return result
        if opts.mode == "replace":
            self._clear_vault()
        existing = {} if opts.mode == "replace" else self._existing_entries_by_identity()
        deadline = start + max(1, int(opts.timeout_seconds))
        for entry in entries:
            if time.monotonic() > deadline:
                raise ImportValidationError("Import timed out")
            ident = self._identity(entry)
            exist = existing.get(ident)
            if exist and opts.duplicate_strategy == "skip":
                result.skipped += 1
            elif exist and opts.duplicate_strategy == "replace":
                self.entry_manager.update_entry(exist["id"], entry)
                result.updated += 1
            else:
                created = self.entry_manager.create_entry(entry)
                existing[ident] = created
                result.created += 1
        result.imported = result.created
        return result

    def _clear_vault(self):
        if hasattr(self.entry_manager, "get_all_entries") and hasattr(self.entry_manager, "delete_entry"):
            for e in list(self.entry_manager.get_all_entries()):
                self.entry_manager.delete_entry(e["id"], soft_delete=False)
        elif hasattr(self.entry_manager, "entries"):
            self.entry_manager.entries = []

    def _record_history(self, op, fmt, enc, cnt, size, chk, status, details):
        if self.database is None:
            return
        self.database.add_import_export_history(
            operation_type=op, format=fmt, encryption_used=enc, entry_count=cnt,
            file_size=size, checksum=chk, verification_status=status, details=details
        )

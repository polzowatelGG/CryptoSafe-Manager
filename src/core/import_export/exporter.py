
import base64
import gzip
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .crypto import checksum, derive_password_key, encrypt_aes_gcm, encrypt_with_public_key, new_salt_and_nonce, wipe_bytes
from .models import ExportOptions
from .formats import BitwardenEncryptedJSONFormat, BitwardenJSONFormat, CSVVaultFormat, LastPassCSVFormat, NativeJSONFormat


class VaultExporter:
    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def get_entries_for_export(self, options: Optional[ExportOptions] = None) -> list[Dict[str, Any]]:
        selected_options = options or ExportOptions()
        if selected_options.entry_ids:
            # Убираем int() – ID у вас строки
            return [self.entry_manager.get_entry(entry_id) for entry_id in selected_options.entry_ids]
        return list(self.entry_manager.get_all_entries())

    def filter_entry_fields(self, entries: Iterable[Dict[str, Any]], include_fields: Optional[list[str]]) -> list[Dict[str, Any]]:
        if not include_fields:
            return [dict(e) for e in entries]
        allowed = set(include_fields)
        return [{k: v for k, v in dict(e).items() if k in allowed} for e in entries]
    
        # -----------------------------------------------------------------------
    # Unified export method for ExportDialog
    # -----------------------------------------------------------------------

    def export(
        self,
        filepath: str,
        password: str,
        format: str = "encrypted_json",
        entry_ids: Optional[List[str]] = None,
        exclude_fields: Optional[List[str]] = None,
        compress: bool = False,
    ) -> int:
        """
        Unified export method that writes result directly to file.
        Returns number of exported entries.
        """
        # Преобразуем exclude_fields в include_fields
        include_fields = None
        if exclude_fields:
            all_fields = {"title", "username", "password", "url", "notes", "category", "tags"}
            include_fields = list(all_fields - set(exclude_fields))

        opts = ExportOptions(
            format=format,
            entry_ids=entry_ids,
            include_fields=include_fields,
            encryption_strength=256,
            compression=compress,
            plaintext_allowed=(format in ("csv", "bitwarden", "lastpass_csv")),
        )

        # Подсчёт количества записей (для возврата)
        entries = self.filter_entry_fields(
            self.get_entries_for_export(opts),
            opts.include_fields,
        )
        count = len(entries)

        # Диспетчеризация по форматам
        if format == "encrypted_json":
            if not password:
                raise ValueError("Password required for encrypted_json export")
            output = self.export_encrypted_json(password, opts)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)

        elif format == "csv":
            if not opts.plaintext_allowed:
                raise ValueError("CSV export requires plaintext_allowed=True")
            output = self.export_csv(opts)
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.write(output)

        elif format == "bitwarden":
            if not opts.plaintext_allowed:
                raise ValueError("Bitwarden export requires plaintext_allowed=True")
            output = self.export_bitwarden_json(opts)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)

        elif format == "bitwarden_encrypted":
            if not password:
                raise ValueError("Password required for bitwarden_encrypted export")
            output = self.export_bitwarden_encrypted_json(password, opts)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)

        elif format == "lastpass_csv":
            if not opts.plaintext_allowed:
                raise ValueError("LastPass CSV export requires plaintext_allowed=True")
            output = self.export_lastpass_csv(opts)
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.write(output)

        else:
            raise ValueError(f"Unsupported export format: {format}")

        return count

    def export_encrypted_json(self, password: str, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions()
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        payload = {"entries": [self._serialize_entry(e) for e in entries], "entry_count": len(entries)}
        payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if opts.compression:
            payload_bytes = gzip.compress(payload_bytes)

        salt, _ = new_salt_and_nonce()
        key = derive_password_key(password, salt, bits=opts.encryption_strength)
        keybuf = bytearray(key)
        try:
            nonce, ciphertext = encrypt_aes_gcm(payload_bytes, keybuf)
            pkg_hmac = hmac.new(bytes(keybuf), ciphertext, "sha256").hexdigest()
        finally:
            wipe_bytes(keybuf)

        pkg = {
            "cryptosafe_export": True,
            "format": NativeJSONFormat.name,
            "version": NativeJSONFormat.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "mode": "selected" if opts.entry_ids else "full",
                "entry_count": len(entries),
                "fields": opts.include_fields or "all",
                "compressed": opts.compression,
            },
            "encryption": {
                "algorithm": "AES-256-GCM" if opts.encryption_strength == 256 else "AES-128-GCM",
                "kdf": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": {"ciphertext": base64.b64encode(ciphertext).decode("ascii")},
            "integrity": {
                "checksum": checksum(ciphertext),
                "payload_checksum": checksum(payload_bytes),
                "hmac": pkg_hmac,
                "signature": pkg_hmac,
            },
        }
        output = NativeJSONFormat().serialize_header(pkg)
        self._record_history("export", "encrypted_json", pkg["encryption"]["algorithm"], len(entries), len(output.encode()), pkg["integrity"]["checksum"], "created", pkg["metadata"])
        return output

    def export_encrypted_json_for_public_key(self, public_key: str, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions()
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        payload = {"entries": [self._serialize_entry(e) for e in entries], "entry_count": len(entries)}
        payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if opts.compression:
            payload_bytes = gzip.compress(payload_bytes)

        encrypted = encrypt_with_public_key(payload_bytes, public_key)
        pkg = {
            "cryptosafe_export": True,
            "format": NativeJSONFormat.name,
            "version": NativeJSONFormat.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "mode": "selected" if opts.entry_ids else "full",
                "entry_count": len(entries),
                "fields": opts.include_fields or "all",
                "compressed": opts.compression,
            },
            "encryption": {
                "algorithm": encrypted["algorithm"],
                "method": encrypted["method"],
                "key_size": encrypted["key_size"],
                "key_fingerprint": encrypted["key_fingerprint"],
                "nonce": encrypted["nonce"],
            },
            "data": {"ciphertext": encrypted["ciphertext"], "encrypted_key": encrypted["encrypted_key"]},
            "integrity": {
                "checksum": encrypted["checksum"],
                "payload_checksum": checksum(payload_bytes),
                "signature": encrypted["checksum"],
            },
        }
        output = NativeJSONFormat().serialize_header(pkg)
        self._record_history("export", "encrypted_json", pkg["encryption"]["algorithm"], len(entries), len(output.encode()), pkg["integrity"]["checksum"], "created", pkg["metadata"])
        return output

    def export_csv(self, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions(format="csv", plaintext_allowed=True)
        if not opts.plaintext_allowed:
            raise ValueError("Plaintext CSV export must be explicitly allowed")
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        output = CSVVaultFormat().serialize_rows(self._serialize_entry(e) for e in entries)
        self._record_history("export", "csv", "none", len(entries), len(output.encode()), checksum(output.encode()), "created", {"plaintext": True})
        return output

    def export_bitwarden_json(self, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions(format="bitwarden_json", plaintext_allowed=True)
        if not opts.plaintext_allowed:
            raise ValueError("Plaintext Bitwarden export must be explicitly allowed")
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        output = BitwardenJSONFormat().serialize_entries([self._serialize_entry(e) for e in entries])
        self._record_history("export", "bitwarden_json", "none", len(entries), len(output.encode()), checksum(output.encode()), "created", {"target": "bitwarden"})
        return output

    def export_bitwarden_encrypted_json(self, password: str, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions(format="bitwarden_encrypted_json")
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        output = BitwardenEncryptedJSONFormat().serialize_entries([self._serialize_entry(e) for e in entries], password)
        self._record_history("export", "bitwarden_encrypted_json", "Bitwarden password-protected JSON", len(entries), len(output.encode()), checksum(output.encode()), "created", {"target": "bitwarden"})
        return output

    def export_lastpass_csv(self, options: Optional[ExportOptions] = None) -> str:
        opts = options or ExportOptions(format="lastpass_csv", plaintext_allowed=True)
        if not opts.plaintext_allowed:
            raise ValueError("Plaintext LastPass export must be explicitly allowed")
        entries = self.filter_entry_fields(self.get_entries_for_export(opts), opts.include_fields)
        output = LastPassCSVFormat().serialize_entries([self._serialize_entry(e) for e in entries])
        self._record_history("export", "lastpass_csv", "none", len(entries), len(output.encode()), checksum(output.encode()), "created", {"target": "lastpass"})
        return output

    def _serialize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        safe = dict(entry)
        for k, v in list(safe.items()):
            if isinstance(v, datetime):
                safe[k] = v.isoformat()
        return safe

    def _record_history(self, op, fmt, enc, cnt, size, chk, status, details):
        if self.database is None:
            return
        self.database.add_import_export_history(
            operation_type=op, format=fmt, encryption_used=enc, entry_count=cnt,
            file_size=size, checksum=chk, verification_status=status, details=details
        )
# src/core/import_export/formats/password_manager.py
import base64
import csv
import io
import json
import os
import uuid
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..exceptions import ImportValidationError

# ---------------------------------------------------------------------------
# Bitwarden encrypted JSON (password-protected)
# ---------------------------------------------------------------------------

BITWARDEN_PASSWORD_PROTECTED_ITERATIONS = 600_000


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive_bitwarden_pin_key(password: str, salt_b64: str, iterations: int) -> bytes:
    # IMPORTANT: Bitwarden uses the base64 salt string as UTF-8 bytes.
    # Do not base64-decode salt_b64 before passing it to PBKDF2.
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_b64.encode("utf-8"),
        iterations=int(iterations),
    ).derive(password.encode("utf-8"))


def _stretch_bitwarden_key(pin_key: bytes) -> tuple[bytes, bytes]:
    enc_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"enc",
    ).derive(pin_key)
    mac_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"mac",
    ).derive(pin_key)
    return enc_key, mac_key


def _encrypt_bitwarden_blob(plaintext: bytes | str, enc_key: bytes, mac_key: bytes) -> str:
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    else:
        data = bytes(plaintext)

    iv = os.urandom(16)
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len]) * pad_len

    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    mac = h.finalize()

    return f"2.{_b64(iv)}|{_b64(ciphertext)}|{_b64(mac)}"


class BitwardenEncryptedJSONFormat:
    name = "bitwarden_encrypted_json"

    def serialize_entries(self, entries: List[Dict[str, Any]], password: str) -> str:
        if not password:
            raise ValueError("Bitwarden encrypted export requires password")

        # Bitwarden password-protected export does not encrypt each item field.
        # It builds a normal Bitwarden JSON export and encrypts the whole JSON
        # into the root-level "data" field.
        plain_export = BitwardenJSONFormat()._build_plain_export(entries)
        plain_json = json.dumps(
            plain_export,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        salt_b64 = _b64(os.urandom(16))
        pin_key = _derive_bitwarden_pin_key(
            password,
            salt_b64,
            BITWARDEN_PASSWORD_PROTECTED_ITERATIONS,
        )
        enc_key, mac_key = _stretch_bitwarden_key(pin_key)

        root = {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt_b64,
            "kdfType": 0,
            "kdfIterations": BITWARDEN_PASSWORD_PROTECTED_ITERATIONS,
            "kdfMemory": None,
            "kdfParallelism": None,
            "encKeyValidation_DO_NOT_EDIT": _encrypt_bitwarden_blob(
                str(uuid.uuid4()),
                enc_key,
                mac_key,
            ),
            "data": _encrypt_bitwarden_blob(
                plain_json,
                enc_key,
                mac_key,
            ),
        }

        return json.dumps(root, ensure_ascii=False, indent=2)

# ---------------------------------------------------------------------------
# Bitwarden plaintext JSON (for migration)
# ---------------------------------------------------------------------------

class BitwardenJSONFormat:
    name = "bitwarden_json"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        return json.dumps(self._build_plain_export(entries), ensure_ascii=False, sort_keys=True)

    def _build_plain_export(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        folders = []
        folder_ids = {}
        for entry in entries:
            cat = entry.get("category", "").strip()
            if cat and cat not in folder_ids:
                folder_ids[cat] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-folder:{cat}"))
                folders.append({"id": folder_ids[cat], "name": cat})

        items = []
        for entry in entries:
            title = entry.get("title", "") or "Untitled"
            category = entry.get("category", "").strip()
            url = entry.get("url", "").strip()
            tags = [{"name": t.strip(), "type": 0, "value": "true"} for t in entry.get("tags", "").split(",") if t.strip()]
            items.append({
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-item:{title}")),
                "organizationId": None,
                "folderId": folder_ids.get(category),
                "type": 1,
                "reprompt": 0,
                "name": title,
                "notes": entry.get("notes", "") or None,
                "favorite": False,
                "login": {
                    "uris": [{"match": None, "uri": url}] if url else [],
                    "username": entry.get("username", "") or None,
                    "password": entry.get("password", "") or None,
                    "totp": None,
                },
                "fields": tags,
            })
        return {"encrypted": False, "folders": folders, "items": items}

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ImportValidationError("Bitwarden JSON is invalid") from e
        if not isinstance(parsed, dict):
            raise ImportValidationError("Bitwarden JSON must be an object")
        folders = parsed.get("folders", [])
        folder_map = {str(f.get("id")): str(f.get("name") or "") for f in folders if isinstance(f, dict)}
        items = parsed.get("items", [])
        if not isinstance(items, list):
            raise ImportValidationError("Bitwarden JSON does not contain items")
        entries = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") not in (None, 1):
                continue
            login = item.get("login") or {}
            uris = login.get("uris") or []
            url = uris[0].get("uri", "") if uris else ""
            fields = item.get("fields") or []
            tags = ",".join(str(f.get("name", "")).strip() for f in fields if isinstance(f, dict) and f.get("name"))
            entries.append({
                "title": item.get("name", ""),
                "username": login.get("username", ""),
                "password": login.get("password", ""),
                "url": url,
                "notes": item.get("notes", "") or "",
                "category": folder_map.get(str(item.get("folderId")), ""),
                "tags": tags,
            })
        return entries


# ---------------------------------------------------------------------------
# LastPass CSV format
# ---------------------------------------------------------------------------

class LastPassCSVFormat:
    name = "lastpass_csv"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        output = io.StringIO(newline="")
        fieldnames = ["url", "username", "password", "extra", "name", "grouping"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "url": entry.get("url", ""),
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "extra": entry.get("notes", ""),
                "name": entry.get("title", ""),
                "grouping": entry.get("category", ""),
            })
        return output.getvalue()

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        from .csv_format import CSVVaultFormat
        # LastPass CSV is just a special CSV, reuse generic parser
        return CSVVaultFormat().parse_rows(payload)
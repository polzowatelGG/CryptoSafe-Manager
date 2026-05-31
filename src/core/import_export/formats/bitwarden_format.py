
# src/core/import_export/formats/bitwarden_format.py
# Compatibility wrapper: the real Bitwarden export formats live in password_manager.py.
# This prevents an old duplicate implementation from producing invalid encrypted JSON.

from .password_manager import BitwardenEncryptedJSONFormat, BitwardenJSONFormat

__all__ = ["BitwardenEncryptedJSONFormat", "BitwardenJSONFormat"]
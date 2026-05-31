
import json
from typing import Any, Dict

from ..exceptions import ImportValidationError


class NativeJSONFormat:
    name = "encrypted_json"
    version = "1.0"

    def serialize_header(self, package: Dict[str, Any]) -> str:
        return json.dumps(package, ensure_ascii=False, sort_keys=True)

    def deserialize_header(self, payload: str) -> Dict[str, Any]:
        parsed = json.loads(payload)
        if not isinstance(parsed, dict):
            raise ValueError("Native JSON export must be a JSON object")
        return parsed

    def is_native_export(self, payload: Dict[str, Any]) -> bool:
        return bool(payload.get("cryptosafe_export"))

    def validate_package(self, package: Dict[str, Any]):
        if not self.is_native_export(package):
            raise ImportValidationError("File is not a CryptoSafe native export")
        required = {"cryptosafe_export", "timestamp", "encryption", "data", "integrity"}
        missing = sorted(required.difference(package))
        if missing:
            raise ImportValidationError(f"Native export missing fields: {', '.join(missing)}")
        for section in ("encryption", "data", "integrity"):
            if not isinstance(package.get(section), dict):
                raise ImportValidationError(f"Native export {section} block is invalid")
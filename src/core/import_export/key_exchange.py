# QR-коды для обмена публичными ключами и зашифрованными пакетами.
# Поддерживает: генерацию QR, chunking больших данных, сканирование из файла.
# Безопасность: временная метка + nonce против replay-атак (QR-4).

import base64
import hashlib
import json
import os
import zlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

try:
    import qrcode
    import qrcode.image.svg
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


# Константы
# Максимальный размер одного QR-чанка в байтах
# Version 40, Error Correction L = 2953 байта
QR_CHUNK_SIZE = 2953

# Время жизни QR-кода по умолчанию (QR-4)
QR_DEFAULT_TTL_SECONDS = 300  # 5 минут

# Типы payload
PAYLOAD_TYPE_PUBLIC_KEY   = "public_key"
PAYLOAD_TYPE_SHARE_PACKAGE = "share_package"
PAYLOAD_TYPE_SHARE_LINK    = "share_link"


# Вспомогательные функции
def _chunk_data(data: bytes, chunk_size: int = QR_CHUNK_SIZE) -> List[bytes]:
    # Разбивает байты на чанки заданного размера
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def _build_chunk_envelope(
    chunk_data: bytes,
    chunk_num: int,
    total_chunks: int,
    session_id: str,
) -> str:
    # Оборачивает чанк в JSON-конверт с метаданными.
    # session_id связывает все чанки одной передачи.
    envelope = {
        "s":  session_id,       # session id — все чанки одной передачи
        "n":  chunk_num,        # номер чанка (1-based)
        "t":  total_chunks,     # всего чанков
        "d":  base64.b64encode(chunk_data).decode("ascii"),
        "cs": hashlib.sha256(chunk_data).hexdigest()[:8],  # контрольная сумма
    }
    return json.dumps(envelope, separators=(",", ":"))


def _verify_chunk_envelope(envelope_str: str) -> Tuple[bool, Optional[Dict]]:
    # Верифицирует чанк: парсит JSON, проверяет контрольную сумму.
    # Возвращает (ok, envelope_dict).
    try:
        env = json.loads(envelope_str)
        data = base64.b64decode(env["d"])
        expected_cs = hashlib.sha256(data).hexdigest()[:8]
        if expected_cs != env["cs"]:
            return False, None
        return True, env
    except Exception:
        return False, None


# Основной класс
class QRCodeService:
    # Сервис для генерации и сканирования QR-кодов.

    # Поддерживаемые payload-типы :
    #     public_key    — публичный ключ для получения зашифрованных шарингов
    #     share_package — зашифрованный пакет записи (небольшой размер)
    #     share_link    — метаданные + share_id для получения через другой канал

    # Безопасность :
    #     - QR не содержит plaintext данных
    #     - Каждый QR содержит timestamp + nonce для защиты от replay
    #     - TTL по умолчанию 5 минут
    #     - Контрольная сумма каждого чанка
    def __init__(self, ttl_seconds: int = QR_DEFAULT_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds


    # Генерация QR-кодов
    def generate_qr_codes(
        self,
        payload_type: str,
        data: Any,
        as_svg: bool = True,
    ) -> List[Dict[str, Any]]:
        # Генерирует один или несколько QR-кодов для передачи данных (QR-1).

        # Args:
        #     payload_type: PAYLOAD_TYPE_* константа
        #     data:         данные для кодирования (dict/bytes/str)
        #     as_svg:       True = SVG, False = PNG (требует Pillow)

        # Returns:
        #     Список словарей:
        #     [{'chunk': 1, 'total': N, 'image': '<svg...>' или bytes,
        #       'session_id': str, 'expires_at': str}]

        # Raises:
        #     ImportError: qrcode не установлен
        #     ValueError:  неизвестный payload_type
        if not QRCODE_AVAILABLE:
            raise ImportError(
                "Библиотека qrcode не установлена. "
                "Выполните: pip install qrcode[pil]"
            )

        if payload_type not in (
            PAYLOAD_TYPE_PUBLIC_KEY,
            PAYLOAD_TYPE_SHARE_PACKAGE,
            PAYLOAD_TYPE_SHARE_LINK,
        ):
            raise ValueError(f"Неизвестный тип payload: {payload_type}")

        # Оборачиваем данные в безопасный конверт (QR-4)
        envelope = self._build_secure_envelope(payload_type, data)
        raw_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

        # Сжимаем для уменьшения размера QR
        compressed = zlib.compress(raw_bytes, level=9)

        # Разбиваем на чанки если нужно
        chunks     = _chunk_data(compressed, QR_CHUNK_SIZE)
        total      = len(chunks)
        session_id = envelope["nonce"][:8]  # используем часть nonce как session_id
        expires_at = envelope["expires_at"]

        result = []
        for i, chunk in enumerate(chunks):
            chunk_str = _build_chunk_envelope(chunk, i + 1, total, session_id)
            image     = self._render_qr(chunk_str, as_svg)
            result.append({
                "chunk":      i + 1,
                "total":      total,
                "image":      image,
                "session_id": session_id,
                "expires_at": expires_at,
                "format":     "svg" if as_svg else "png",
            })

        return result

    def generate_public_key_qr(
        self, public_key_pem: bytes, as_svg: bool = True
    ) -> List[Dict[str, Any]]:
        # Удобный метод для генерации QR публичного ключа 
        return self.generate_qr_codes(
            payload_type=PAYLOAD_TYPE_PUBLIC_KEY,
            data={"public_key_pem": base64.b64encode(public_key_pem).decode("ascii")},
            as_svg=as_svg,
        )

    def generate_share_qr(
        self, share_package: Dict[str, Any], as_svg: bool = True
    ) -> List[Dict[str, Any]]:

        # Удобный метод для генерации QR пакета шаринга 
        return self.generate_qr_codes(
            payload_type=PAYLOAD_TYPE_SHARE_PACKAGE,
            data=share_package,
            as_svg=as_svg,
        )

    # Сканирование QR-кодов
    def scan_qr_from_file(self, image_path: str) -> Optional[Dict[str, Any]]:
        # Сканирует QR-код из файла изображения (QR-2).

        # Args:
        #     image_path: путь к PNG/JPG файлу с QR-кодом

        # Returns:
        #     Расшифрованный payload или None если не удалось

        # Raises:
        #     ImportError: pyzbar или Pillow не установлены
        #     FileNotFoundError: файл не найден
        if not PIL_AVAILABLE:
            raise ImportError(
                "Библиотека Pillow не установлена. "
                "Выполните: pip install Pillow"
            )
        if not PYZBAR_AVAILABLE:
            raise ImportError(
                "Библиотека pyzbar не установлена. "
                "Выполните: pip install pyzbar"
            )

        import os
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Файл не найден: {image_path}")

        try:
            image   = Image.open(image_path)
            decoded = pyzbar.decode(image)
        except Exception as e:
            raise ValueError(f"Не удалось прочитать QR-код из файла: {e}")

        if not decoded:
            return None

        # Берём первый найденный QR
        qr_data = decoded[0].data.decode("utf-8")
        return self._decode_single_chunk(qr_data)

    def decode_chunks(self, chunk_strings: List[str]) -> Optional[Dict[str, Any]]:
        # Декодирует и собирает данные из нескольких QR-чанков (QR-2).

        # Args:
        #     chunk_strings: список строк из QR-кодов (порядок не важен)

        # Returns:
        #     Восстановленный payload или None при ошибке
        # Верифицируем и парсим все чанки
        validated: Dict[int, bytes] = {}  # chunk_num → data
        session_id = None

        for chunk_str in chunk_strings:
            ok, env = _verify_chunk_envelope(chunk_str)
            if not ok:
                return None

            # Проверяем что все чанки из одной сессии
            if session_id is None:
                session_id = env["s"]
            elif env["s"] != session_id:
                return None  # чанки из разных сессий

            chunk_num = env["n"]
            validated[chunk_num] = base64.b64decode(env["d"])

        if not validated:
            return None

        # Проверяем полноту набора
        total = max(validated.keys())
        if set(validated.keys()) != set(range(1, total + 1)):
            return None  # не все чанки получены

        # Собираем и распаковываем
        compressed = b"".join(validated[i] for i in range(1, total + 1))
        try:
            raw_bytes = zlib.decompress(compressed)
            envelope  = json.loads(raw_bytes.decode("utf-8"))
        except Exception:
            return None

        return self._verify_and_extract(envelope)

    # Внутренние методы
    def _build_secure_envelope(
        self, payload_type: str, data: Any
    ) -> Dict[str, Any]:
        # Оборачивает данные в безопасный конверт :
        # - timestamp для проверки TTL
        # - nonce для защиты от replay
        # - тип payload
        # - хэш данных для верификации целостности
        # Сериализуем данные
        if isinstance(data, bytes):
            data_encoded = base64.b64encode(data).decode("ascii")
            data_is_bytes = True
        else:
            data_encoded  = data
            data_is_bytes = False

        now        = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.ttl_seconds)
        nonce      = base64.b64encode(os.urandom(16)).decode("ascii")

        # Хэш данных для верификации целостности 
        data_str  = json.dumps(data_encoded, sort_keys=True, ensure_ascii=False)
        data_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

        return {
            "version":      "1.0",
            "payload_type": payload_type,
            "created_at":   now.isoformat() + "Z",
            "expires_at":   expires_at.isoformat() + "Z",
            "nonce":        nonce,
            "data_hash":    data_hash,
            "is_bytes":     data_is_bytes,
            "data":         data_encoded,
        }

    def _verify_and_extract(
        self, envelope: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        # Верифицирует конверт и извлекает данные:
        # - проверяет хэш данных 
        # - проверяет TTL 
        # Проверяем срок действия 
        expires_at_str = envelope.get("expires_at", "")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    expires_at_str.replace("Z", "+00:00")
                ).replace(tzinfo=None)
                if datetime.utcnow() > expires_at:
                    return None  # QR истёк
            except Exception:
                pass

        # Проверяем хэш данных 
        data         = envelope.get("data")
        expected_hash = envelope.get("data_hash")
        if expected_hash:
            data_str   = json.dumps(data, sort_keys=True, ensure_ascii=False)
            computed   = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
            if computed != expected_hash:
                return None  # данные повреждены

        # Декодируем bytes если нужно
        if envelope.get("is_bytes") and isinstance(data, str):
            data = base64.b64decode(data)

        return {
            "payload_type": envelope.get("payload_type"),
            "created_at":   envelope.get("created_at"),
            "expires_at":   envelope.get("expires_at"),
            "data":         data,
        }

    def _decode_single_chunk(self, qr_data: str) -> Optional[Dict[str, Any]]:
        # Декодирует одиночный QR-чанк (для случая когда данные умещаются в 1 QR).
        ok, env = _verify_chunk_envelope(qr_data)
        if not ok:
            return None

        chunk_data = base64.b64decode(env["d"])
        # Если это единственный чанк — собираем сразу
        if env.get("t", 1) == 1:
            try:
                raw_bytes = zlib.decompress(chunk_data)
                envelope  = json.loads(raw_bytes.decode("utf-8"))
                return self._verify_and_extract(envelope)
            except Exception:
                return None

        # Многочанковый QR — нужны все чанки
        return None

    def _render_qr(self, data: str, as_svg: bool) -> Any:
        # Рендерит QR-код из строки.
        # Возвращает SVG-строку или PNG-байты.
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        if as_svg:
            factory = qrcode.image.svg.SvgImage
            img     = qr.make_image(image_factory=factory)
            # to_string() возвращает bytes в qrcode >= 7.x
            svg_bytes = img.to_string()
            return svg_bytes.decode("utf-8") if isinstance(svg_bytes, bytes) else svg_bytes
        else:
            if not PIL_AVAILABLE:
                raise ImportError(
                    "Pillow не установлен. Используйте as_svg=True "
                    "или выполните: pip install Pillow"
                )
            import io
            img    = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            return buffer.getvalue()

    # Утилиты
    def get_qr_info(self, qr_result: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Возвращает информацию о сгенерированном QR для UI (QR viewer).
        if not qr_result:
            return {}
        first = qr_result[0]
        return {
            "total_chunks": first["total"],
            "session_id":   first["session_id"],
            "expires_at":   first["expires_at"],
            "format":       first["format"],
            "is_multi":     first["total"] > 1,
        }

    def is_qr_available(self) -> bool:
        # Проверяет доступность библиотек для QR
        return QRCODE_AVAILABLE

    def is_scan_available(self) -> bool:
        # Проверяет доступность библиотек для сканирования QR
        return PIL_AVAILABLE and PYZBAR_AVAILABLE
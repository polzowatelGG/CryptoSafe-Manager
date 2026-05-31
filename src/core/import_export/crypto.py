
import base64
import hashlib
import hmac
import os
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import ImportValidationError


def random_bytes(length: int) -> bytes:
    return os.urandom(max(1, int(length)))


def derive_password_key(password: str, salt: bytes, *, bits: int = 256, iterations: int = 100000) -> bytes:
    if bits not in {128, 256}:
        raise ValueError("Encryption strength must be 128 or 256 bits")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=bits // 8,
        salt=bytes(salt),
        iterations=max(100000, int(iterations)),
    )
    return kdf.derive(str(password).encode("utf-8"))


def derive_separated_key(source_key: bytes, context: bytes, *, bits: int = 256) -> bytes:
    if bits not in {128, 256}:
        raise ValueError("Encryption strength must be 128 or 256 bits")
    digest = hmac.new(bytes(source_key), bytes(context), hashlib.sha256).digest()
    return digest[: bits // 8]


def wipe_bytes(buffer: bytearray | memoryview) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def checksum(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def new_salt_and_nonce() -> Tuple[bytes, bytes]:
    return random_bytes(16), random_bytes(12)


def encrypt_aes_gcm(plaintext: bytes, key: bytes, *, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    nonce = random_bytes(12)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), bytes(associated_data))
    return nonce, ciphertext


def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, *, associated_data: bytes = b"") -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(associated_data))
    except InvalidTag as exc:
        raise ImportValidationError("Encrypted data failed authentication") from exc


def generate_rsa_key_pair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem.decode("ascii"), public_pem.decode("ascii")


def generate_ec_key_pair() -> Tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem.decode("ascii"), public_pem.decode("ascii")


def public_key_fingerprint(public_key_pem: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(str(public_key_pem).encode("utf-8"))
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        key_bytes = str(public_key_pem).encode("utf-8")
    digest = hashlib.sha256(key_bytes).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, 32, 2))


def encrypt_with_public_key(plaintext: bytes, public_key_pem: str, *, associated_data: bytes = b"") -> Dict[str, str]:
    public_key = serialization.load_pem_public_key(str(public_key_pem).encode("utf-8"))
    content_key = random_bytes(32)
    nonce, ciphertext = encrypt_aes_gcm(plaintext, content_key, associated_data=associated_data)
    encrypted_key = public_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "algorithm": "RSA-OAEP/AES-256-GCM",
        "method": "public_key",
        "key_size": "2048",
        "key_fingerprint": public_key_fingerprint(public_key_pem),
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "checksum": checksum(ciphertext),
    }


def decrypt_with_private_key(package: Dict[str, str], private_key_pem: str, *, associated_data: bytes = b"") -> bytes:
    try:
        encrypted_key = base64.b64decode(package["encrypted_key"])
        nonce = base64.b64decode(package["nonce"])
        ciphertext = base64.b64decode(package["ciphertext"])
    except Exception as e:
        raise ImportValidationError("Public-key package contains invalid base64 data") from e
    if checksum(ciphertext) != package.get("checksum", ""):
        raise ImportValidationError("Public-key package checksum mismatch")
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    content_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypt_aes_gcm(ciphertext, content_key, nonce, associated_data=associated_data)

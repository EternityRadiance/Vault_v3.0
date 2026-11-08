from __future__ import annotations

import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = PROJECT_ROOT / "keys"
PRIVATE_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_PATH = KEYS_DIR / "rsa_public.pem"

KEY_SIZE = 2048

def generate() -> None:
    """Формирует строки CSV-выгрузки событий аудита.

    Возвращает:
        None (значение не возвращается).
    """
    KEYS_DIR.mkdir(exist_ok=True)

    if PRIVATE_PATH.exists():
        print(f"[skip] {PRIVATE_PATH} already exists")
        print("     delete it manually to regenerate")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_PATH.write_bytes(private_pem)

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_PATH.write_bytes(public_pem)

    os.chmod(PRIVATE_PATH, 0o600)
    os.chmod(PUBLIC_PATH, 0o644)


    print(f"[ok] private key: {PRIVATE_PATH}")
    print(f"[ok] public key: {PUBLIC_PATH}")
    print(f"    key size:   {KEY_SIZE} bits")

if __name__ == "__main__":
    generate()
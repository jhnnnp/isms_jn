from __future__ import annotations

import base64
import binascii
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _normalize_key(key: str) -> bytes:
    try:
        raw_key = bytes.fromhex(key)
    except ValueError:
        raw_key = sha256(key.encode("utf-8")).digest()

    if len(raw_key) not in {16, 24, 32}:
        raise ValueError("AES key must resolve to 16, 24, or 32 bytes.")
    return raw_key


def encrypt_text(value: str, key: str) -> str:
    raw_key = _normalize_key(key)
    nonce = get_random_bytes(12)
    cipher = AES.new(raw_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
    payload = nonce + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def decrypt_text(token: str, key: str) -> str:
    raw_key = _normalize_key(key)
    try:
        payload = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce = payload[:12]
        tag = payload[12:28]
        ciphertext = payload[28:]
        cipher = AES.new(raw_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid encrypted token.") from error

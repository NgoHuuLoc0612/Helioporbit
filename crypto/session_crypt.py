"""
helioporbit.crypto.session_crypt
Encrypts / decrypts the .hpb session artefact.

Format (binary):
  [4B magic] [1B version] [32B salt] [12B nonce] [16B tag] [N bytes ciphertext]

Encryption: PBKDF2-SHA512 (600k iters) → ChaCha20-Poly1305
"""

from __future__ import annotations

import struct
from helioporbit.crypto.primitives import (
    pbkdf2,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
    secure_random_bytes,
)

MAGIC      = b"HPOB"
VERSION    = b"\x02"
SALT_LEN   = 32
NONCE_LEN  = 12
TAG_LEN    = 16
PBKDF2_N   = 600_000
KEY_LEN    = 32

HEADER_FMT  = f">{len(MAGIC)}s{len(VERSION)}s{SALT_LEN}s{NONCE_LEN}s{TAG_LEN}s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def _derive_key(password: str, salt: bytes) -> bytes:
    return pbkdf2(password, salt, iterations=PBKDF2_N, length=KEY_LEN)


def encrypt_session(plaintext: bytes, password: str, path: str) -> None:
    salt  = secure_random_bytes(SALT_LEN)
    nonce = secure_random_bytes(NONCE_LEN)
    key   = _derive_key(password, salt)

    aad = MAGIC + VERSION + salt + nonce
    ct, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad=aad)

    with open(path, "wb") as fh:
        fh.write(struct.pack(HEADER_FMT, MAGIC, VERSION, salt, nonce, tag))
        fh.write(ct)


def decrypt_session(path: str, password: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read()

    if len(raw) < HEADER_SIZE:
        raise ValueError("Session file is truncated / not a valid .hpb file")

    magic, version, salt, nonce, tag = struct.unpack_from(HEADER_FMT, raw)

    if magic != MAGIC:
        raise ValueError(f"Bad magic: expected {MAGIC!r}, got {magic!r}")
    if version != VERSION:
        raise ValueError(f"Unsupported session version: {version!r}")

    ct  = raw[HEADER_SIZE:]
    key = _derive_key(password, salt)
    aad = MAGIC + VERSION + salt + nonce

    return chacha20_poly1305_decrypt(key, nonce, ct, tag, aad=aad)

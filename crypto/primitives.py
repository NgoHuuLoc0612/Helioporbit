"""
helioporbit.crypto.primitives
Low-level cryptographic primitives used across the obfuscation pipeline.
Pure-Python fallback + PyCryptodome fast path when available.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# ChaCha20 — pure Python (RFC 7539)
# ──────────────────────────────────────────────────────────────────────────────

def _rotate32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _chacha20_quarter(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotate32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotate32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotate32(d,  8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotate32(b,  7)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate a 64-byte ChaCha20 keystream block."""
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words  = list(struct.unpack_from("<8I", key))
    nonce_words = list(struct.unpack_from("<3I", nonce))

    state = constants + key_words + [counter] + nonce_words
    working = list(state)

    for _ in range(10):  # 20 rounds = 10 double-rounds
        working[0], working[4], working[ 8], working[12] = _chacha20_quarter(working[0], working[4], working[ 8], working[12])
        working[1], working[5], working[ 9], working[13] = _chacha20_quarter(working[1], working[5], working[ 9], working[13])
        working[2], working[6], working[10], working[14] = _chacha20_quarter(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = _chacha20_quarter(working[3], working[7], working[11], working[15])
        working[0], working[5], working[10], working[15] = _chacha20_quarter(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = _chacha20_quarter(working[1], working[6], working[11], working[12])
        working[2], working[7], working[ 8], working[13] = _chacha20_quarter(working[2], working[7], working[ 8], working[13])
        working[3], working[4], working[ 9], working[14] = _chacha20_quarter(working[3], working[4], working[ 9], working[14])

    output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *output)


def chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes, counter: int = 0) -> bytes:
    """Encrypt/decrypt plaintext using ChaCha20 (RFC 7539). Key=32B, Nonce=12B."""
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20 nonce must be 12 bytes, got {len(nonce)}")

    # Try fast path via PyCryptodome
    try:
        from Crypto.Cipher import ChaCha20
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.encrypt(plaintext)
    except ImportError:
        pass

    result = bytearray()
    for i, block_start in enumerate(range(0, len(plaintext), 64)):
        keystream = _chacha20_block(key, counter + i, nonce)
        block     = plaintext[block_start:block_start + 64]
        result   += bytes(a ^ b for a, b in zip(block, keystream))
    return bytes(result)


chacha20_decrypt = chacha20_encrypt  # symmetric


# ──────────────────────────────────────────────────────────────────────────────
# AES-CTR (128-bit) — PyCryptodome required for this path
# ──────────────────────────────────────────────────────────────────────────────

def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """AES-128-CTR. Key=16B, Nonce=16B."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        ctr    = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(plaintext)
    except ImportError:
        # Fallback: use ChaCha20 with truncated key
        return chacha20_encrypt(key[:16].ljust(32, b"\x00"), nonce[:12], plaintext)


aes_ctr_decrypt = aes_ctr_encrypt  # CTR is symmetric


# ──────────────────────────────────────────────────────────────────────────────
# Multi-layer XOR
# ──────────────────────────────────────────────────────────────────────────────

def xor_multi_encrypt(key: bytes, plaintext: bytes, rounds: int = 3) -> bytes:
    """
    Multiple rounds of XOR with key-derived streams.
    Each round's stream is derived solely from (key, round_index) — making
    the scheme fully symmetric: encrypt == decrypt.
    """
    buf = bytearray(plaintext)
    for r in range(rounds):
        # Derive round subkey from master key + round index (deterministic)
        round_key = hashlib.sha512(key + r.to_bytes(4, "little") + b"xor_round").digest()
        stream    = hashlib.shake_256(round_key).digest(len(buf))
        buf       = bytearray(a ^ b for a, b in zip(buf, stream))
    return bytes(buf)


xor_multi_decrypt = xor_multi_encrypt  # fully symmetric: f(f(x)) == x


# ──────────────────────────────────────────────────────────────────────────────
# PBKDF2-SHA512
# ──────────────────────────────────────────────────────────────────────────────

def pbkdf2(password: str, salt: bytes, iterations: int = 600_000, length: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, dklen=length)


# ──────────────────────────────────────────────────────────────────────────────
# HKDF-SHA512
# ──────────────────────────────────────────────────────────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 64
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm    = b""
    t      = b""
    i      = 0
    while len(okm) < length:
        i  += 1
        t   = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ──────────────────────────────────────────────────────────────────────────────
# Poly1305 MAC (pure Python)
# ──────────────────────────────────────────────────────────────────────────────

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """RFC 8439 Poly1305. Key must be 32 bytes."""
    P   = (1 << 130) - 5
    r   = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s   = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n     = int.from_bytes(chunk + b"\x01", "little")
        acc   = (acc + n) % P
        acc   = (r * acc) % P
    acc = (acc + s) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return acc.to_bytes(16, "little")


# ──────────────────────────────────────────────────────────────────────────────
# Authenticated Encryption (ChaCha20-Poly1305)
# ──────────────────────────────────────────────────────────────────────────────

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Returns (ciphertext, 16-byte tag)."""
    try:
        from Crypto.Cipher import ChaCha20_Poly1305
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct, tag
    except ImportError:
        pass

    # Pure-Python fallback
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    ct       = chacha20_encrypt(key, nonce, plaintext, counter=1)

    pad = lambda n: b"\x00" * ((-n) % 16)
    mac_data = (
        aad + pad(len(aad))
        + ct + pad(len(ct))
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ct))
    )
    tag = poly1305_mac(poly_key, mac_data)
    return ct, tag


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify tag. Raises ValueError on authentication failure."""
    try:
        from Crypto.Cipher import ChaCha20_Poly1305
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ImportError:
        pass

    poly_key = _chacha20_block(key, 0, nonce)[:32]
    pad      = lambda n: b"\x00" * ((-n) % 16)
    mac_data = (
        aad + pad(len(aad))
        + ciphertext + pad(len(ciphertext))
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    expected_tag = poly1305_mac(poly_key, mac_data)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Poly1305 authentication failed — session file is corrupt or password is wrong")
    return chacha20_encrypt(key, nonce, ciphertext, counter=1)


# ──────────────────────────────────────────────────────────────────────────────
# Secure random helpers
# ──────────────────────────────────────────────────────────────────────────────

def secure_random_bytes(n: int) -> bytes:
    return os.urandom(n)


def secure_random_int(lo: int, hi: int) -> int:
    import secrets
    return secrets.randbelow(hi - lo) + lo

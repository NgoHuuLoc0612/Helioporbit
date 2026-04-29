"""
helioporbit.crypto.bytecode_encryptor
Python-side of the encrypted bytecode system.

Workflow:
  1. Take original Python source
  2. compile() -> code object
  3. marshal.dumps() -> bytes
  4. ChaCha20-encrypt bytes with per-module key (derived from session master key)
  5. Emit a loader stub that calls helioporbit_loader.exec_encrypted(blob, key, nonce)

The emitted stub looks like:
    import helioporbit_loader as _hbl
    _hbl.exec_encrypted(
        b'<encrypted_bytes>',
        b'<32_byte_key>',
        b'<12_byte_nonce>',
        globals()
    )

For lazy registration (multiple modules):
    _hbl.register('my_module', b'<blob>', b'<key>', b'<nonce>')
    # ... later, on first use:
    _hbl.exec('my_module', globals())

The C extension handles lazy decryption: each blob is decrypted only
on first access, and the plaintext is discarded from C heap after exec.
"""

from __future__ import annotations

import ast
import base64
import marshal
import os
import secrets
import sys
import tempfile
from typing import Optional, Tuple

from helioporbit.crypto.primitives import (
    chacha20_encrypt,
    hkdf,
    secure_random_bytes,
)


# ── Core encryption ───────────────────────────────────────────────────────────

def compile_and_encrypt(
    source: str,
    filename: str,
    master_key: bytes,
    module_name: str = "<protected>",
) -> Tuple[bytes, bytes, bytes]:
    """
    Compile source → marshal → encrypt.

    Returns:
        (encrypted_blob, key_32bytes, nonce_12bytes)
    """
    # Derive a per-module key via HKDF
    key   = hkdf(master_key, b"bytecode_key",
                 info=module_name.encode(), length=32)
    nonce = secure_random_bytes(12)

    # Compile source to code object
    code  = compile(source, filename, "exec", optimize=1)
    raw   = marshal.dumps(code)

    # Encrypt
    ct = chacha20_encrypt(key, nonce, raw, counter=1)
    return ct, key, nonce


def make_exec_stub(
    blob: bytes,
    key:  bytes,
    nonce: bytes,
    module_name: str = "<protected>",
) -> str:
    """
    Generate a Python stub that uses the C extension to decrypt and exec.

    The stub is designed to be the entire content of the protected .py file.
    It requires helioporbit_loader to be compiled and installed.
    """
    b64_blob  = base64.b85encode(blob).decode()
    b64_key   = base64.b85encode(key).decode()
    b64_nonce = base64.b85encode(nonce).decode()

    stub = (
        "# Helioporbit protected module -- do not edit\n"
        "import base64 as _b85\n"
        "try:\n"
        "    import helioporbit_loader as _hbl\n"
        "    _hbl.exec_encrypted(\n"
        "        _b85.b85decode(" + repr(b64_blob) + "),\n"
        "        _b85.b85decode(" + repr(b64_key)  + "),\n"
        "        _b85.b85decode(" + repr(b64_nonce) + "),\n"
        "        globals()\n"
        "    )\n"
        "except ImportError:\n"
        "    raise ImportError(\n"
        "        'helioporbit_loader C extension not found. '\n"
        "        'Build it with: python setup_loader.py build_ext --inplace'\n"
        "    )\n"
    )
    return stub


def make_lazy_register_stub(
    name:  str,
    blob:  bytes,
    key:   bytes,
    nonce: bytes,
) -> str:
    """
    Generate a registration call (for lazy loading).
    Multiple modules can be registered at startup, decrypted on demand.
    """
    b64_blob  = base64.b85encode(blob).decode()
    b64_key   = base64.b85encode(key).decode()
    b64_nonce = base64.b85encode(nonce).decode()

    return (
        "import base64 as _b85\n"
        "import helioporbit_loader as _hbl\n"
        "_hbl.register(\n"
        "    " + repr(name) + ",\n"
        "    _b85.b85decode(" + repr(b64_blob) + "),\n"
        "    _b85.b85decode(" + repr(b64_key)  + "),\n"
        "    _b85.b85decode(" + repr(b64_nonce) + "),\n"
        ")\n"
    )


# ── File-level API ────────────────────────────────────────────────────────────

def encrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    master_key: Optional[bytes] = None,
    module_name: Optional[str] = None,
) -> Tuple[str, bytes, bytes, bytes]:
    """
    Read a .py file, compile+encrypt it, write an exec stub.

    Returns:
        (output_path, blob, key, nonce)
    """
    src  = Path(input_path).read_text(encoding="utf-8")
    mname = module_name or Path(input_path).stem
    mkey  = master_key  or secure_random_bytes(32)

    blob, key, nonce = compile_and_encrypt(src, input_path, mkey, mname)
    stub = make_exec_stub(blob, key, nonce, mname)

    out = output_path or str(Path(input_path).with_suffix(".hpbc.py"))
    Path(out).write_text(stub, encoding="utf-8")
    return out, blob, key, nonce


# ── Integration with obfuscation pipeline ────────────────────────────────────

class BytecodeEncryptorTransform:
    """
    Used at the END of the obfuscation pipeline:
    takes the already-obfuscated Python source and produces an
    encrypted-bytecode stub instead of emitting the obfuscated source directly.

    This adds a final layer: even if someone reverse-engineers the obfuscated
    source, they still get encrypted bytecode that requires the C extension
    to decrypt.

    Usage in Obfuscator._run_pipeline (final step):
        if cfg.encrypt_bytecode:
            bce = BytecodeEncryptorTransform(session)
            final_source = bce.transform(obfuscated_source)
        else:
            final_source = obfuscated_source
    """

    def __init__(self, master_key: bytes, module_name: str = "<protected>"):
        self.master_key  = master_key
        self.module_name = module_name

    def transform(self, obfuscated_source: str) -> str:
        """
        Compile the obfuscated Python source and emit an exec stub.
        Returns the stub source (which is the final protected output).
        """
        try:
            blob, key, nonce = compile_and_encrypt(
                obfuscated_source,
                "<helioporbit>",
                self.master_key,
                self.module_name,
            )
            return make_exec_stub(blob, key, nonce, self.module_name)
        except SyntaxError as exc:
            raise RuntimeError(
                "bytecode encryption failed — source has syntax errors: " + str(exc)
            ) from exc

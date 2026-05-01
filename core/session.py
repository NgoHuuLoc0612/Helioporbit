"""
Helioporbit ObfuscationSession
Manages the full lifecycle of an obfuscation run: seed derivation, key material,
transform ordering, and reversibility metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

HELIOPORBIT_MAGIC = b"HPOB"
SESSION_VERSION   = 2
PBKDF2_ITERS      = 600_000
SALT_BYTES        = 32
KEY_BYTES         = 64   # 512-bit master key


# ──────────────────────────────────────────────────────────────────────────────
# Transform ordering — deterministic from session seed
# ──────────────────────────────────────────────────────────────────────────────

ALL_TRANSFORMS = [
    "string_encrypt",
    "name_mangle",
    "control_flow_flatten",
    "opaque_predicates",
    "dead_code_inject",
    "integer_encode",
    "unicode_escape",
    "lambda_convert",
    "builtin_rename",
    "docstring_strip",
    "comment_strip",
    "anti_debug",
    "bytecode_poison_comment",
    "junk_import",
    "shuffle_body",
]


@dataclass
class TransformConfig:
    """Per-transform fine-grained tuning knobs."""
    string_encrypt_algo: str       = "chacha"          # chacha | aes_ctr | xor_multi
    name_mangle_style: str         = "hash"            # hash | unicode | phonetic | numeric
    name_mangle_prefix: str        = "_h"
    cff_dispatch: str              = "while_switch"    # while_switch | goto_sim | coroutine
    opaque_complexity: int         = 4                 # 1-10
    dead_code_ratio: float         = 0.35              # 0.0-1.0
    integer_encode_depth: int      = 3
    junk_import_count: int         = 8
    anti_debug_mode: str           = "aggressive"      # passive | aggressive
    shuffle_seed_offset: int       = 0
    unicode_mode: str              = "mixed"           # full | partial | mixed
    # Wordlist mangling (v2)
    wordlist_path: str             = ""               # path to wordlist file; empty = built-in
    use_wordlist: bool             = False            # enable wordlist-based name mangling
    string_split_probability: float = 0.70            # chance to split/encode each string
    junk_class_count: int          = 3                # fake classes to inject
    junk_func_count: int           = 4                # fake functions to inject
    comment_pollution_density: float = 0.20           # comment injection density 0-1
    # Secret fragmentation (v2)
    secret_fragment: bool          = True             # fragment secret-looking strings
    secret_fragment_min: int       = 3                # min fragments per secret
    secret_fragment_max: int       = 6                # max fragments per secret
    # Function splitting (v2)
    function_split: bool           = True             # split large functions
    function_split_min_stmts: int  = 6                # min stmts to trigger split
    function_split_probability: float = 0.85          # chance to split each eligible fn
    # Literal encoding (v2)
    literal_encode: bool           = True             # encode bool/None/bytes/float
    literal_encode_probability: float = 0.75          # per-literal encode chance
    # Bytecode encryption (v2) - requires C extension
    encrypt_bytecode: bool         = False            # final bytecode encryption layer
    # MBA encoding (v3) — Z3-verified Mixed Boolean-Arithmetic
    mba_encode: bool               = True             # enable MBA integer encoding
    mba_probability: float         = 0.80             # fraction of eligible constants
    mba_depth: int                 = 2                # MBA expression recursion depth
    mba_use_z3_linear: bool        = True             # use Z3-guided linear MBA
    mba_z3_timeout_ms: int         = 2000             # Z3 solver timeout per query
    # Anti-Tamper v2 (v3) — passive detection, clean exit
    anti_tamper: bool              = True             # enable anti-tamper layers
    anti_tamper_layers: str        = "1,3,4"          # comma-separated layer numbers
    anti_tamper_inline_guards: bool = True            # inject per-function guards


@dataclass
class ObfuscationSession:
    """
    Central artefact that ties together all reversibility information.

    The session file (*.hpb) is the only artefact needed for deobfuscation.
    It is itself encrypted with a user-supplied password via PBKDF2+ChaCha20.
    """

    session_id: str            = field(default_factory=lambda: secrets.token_hex(16))
    created_at: float          = field(default_factory=time.time)
    version: int               = SESSION_VERSION

    # Cryptographic material (stored encrypted in .hpb)
    master_key_hex: str        = field(default_factory=lambda: secrets.token_hex(KEY_BYTES))
    salt_hex: str              = field(default_factory=lambda: secrets.token_hex(SALT_BYTES))
    nonce_hex: str             = field(default_factory=lambda: secrets.token_hex(16))

    # Name mapping table  {original -> mangled}
    name_map: Dict[str, str]   = field(default_factory=dict)
    # Reverse name map    {mangled -> original}
    reverse_name_map: Dict[str, str] = field(default_factory=dict)

    # String table: {placeholder -> {algo, encrypted_b64, key_b64, nonce_b64}}
    string_table: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # Control flow block ordering per function: {func_name -> [original_block_order]}
    cff_map: Dict[str, List[int]] = field(default_factory=dict)

    # Integer encoding map: {encoded_expr -> original_value}
    int_map: Dict[str, int]    = field(default_factory=dict)

    # Transform execution order (as applied)
    transform_order: List[str] = field(default_factory=list)

    # Config used
    config: Dict[str, Any]     = field(default_factory=dict)

    # Source fingerprint (SHA-256 of original source)
    source_hash: str           = ""

    # ── helpers ────────────────────────────────────────────────────────────────

    def derive_subkey(self, purpose: str, length: int = 32) -> bytes:
        """Derive a purpose-specific subkey via HKDF-like HMAC expansion."""
        master = bytes.fromhex(self.master_key_hex)
        return hmac.new(master, purpose.encode(), hashlib.sha512).digest()[:length]

    def register_name(self, original: str, mangled: str) -> None:
        self.name_map[original] = mangled
        self.reverse_name_map[mangled] = original

    def register_string(self, placeholder: str, meta: Dict[str, str]) -> None:
        self.string_table[placeholder] = meta

    def register_int(self, expr: str, value: int) -> None:
        self.int_map[expr] = value

    def register_cff(self, func_name: str, block_order: List[int]) -> None:
        self.cff_map[func_name] = block_order

    # ── serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ObfuscationSession":
        # config might contain a nested dict
        s = cls.__new__(cls)
        s.__dict__.update(d)
        return s

    def save_encrypted(self, path: str, password: str) -> None:
        """Serialize and encrypt the session to *path* using password."""
        from helioporbit.crypto.session_crypt import encrypt_session
        raw = json.dumps(self.to_dict(), separators=(",", ":")).encode()
        encrypt_session(raw, password, path)

    @classmethod
    def load_encrypted(cls, path: str, password: str) -> "ObfuscationSession":
        """Load and decrypt a session from *path* using password."""
        from helioporbit.crypto.session_crypt import decrypt_session
        raw = decrypt_session(path, password)
        d   = json.loads(raw.decode())
        return cls.from_dict(d)

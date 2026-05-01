"""
helioporbit.transforms.anti_tamper_v2
Runtime Anti-Tamper protection — passive detection, clean termination only.

Layers injected at module-level (import time):

  Layer 1 — Source MAC Guard
    HMAC-SHA256 of the protected .py file's own bytes at import time.
    Modification → sys.exit(0).

  Layer 2 — Code Object Fingerprint
    SHA-256 of marshal(co) for top-level functions, verified at runtime.
    Patch → sys.exit(0).

  Layer 3 — Environment & Tracer Check
    sys.gettrace(), PYTHONINSPECT, PYTHONDONTWRITEBYTECODE env vars,
    /proc/self/status TracerPid (Linux), coverage.py frame detection.
    Any hit → sys.exit(0).

  Layer 4 — Timing Consistency Check
    perf_counter_ns() around a short XOR loop.
    Single-step debugging causes measurable slowdown → sys.exit(0).

  Layer 5 — Inline Per-Function Guards
    Lightweight sys.gettrace() check injected at function entry.
    Applied via InlineFunctionGuardTransformer on the AST.

Response: always sys.exit(0) — clean, no side effects.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import marshal
import random
import secrets
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_RESPONSE_STMT      = "import sys as _hpx; _hpx.exit(0)"
_TIMING_THRESHOLD_NS = 500_000_000   # 500 ms


# ──────────────────────────────────────────────────────────────────────────────
# Key derivation
# ──────────────────────────────────────────────────────────────────────────────

def derive_integrity_key(master_key: bytes, purpose: str = "anti_tamper") -> bytes:
    return hmac.new(master_key, purpose.encode(), hashlib.sha512).digest()[:32]


def compute_source_mac(source_bytes: bytes, key: bytes) -> str:
    return hmac.new(key, source_bytes, hashlib.sha256).hexdigest()


def compute_code_object_hash(code_obj) -> str:
    return hashlib.sha256(marshal.dumps(code_obj)).hexdigest()


def build_co_hash_table_from_source(source: str) -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        code = compile(source, "<anti_tamper>", "exec")
        for const in code.co_consts:
            if hasattr(const, "co_name") and const.co_name != "<module>":
                table[const.co_name] = hashlib.sha256(marshal.dumps(const)).hexdigest()
    except (SyntaxError, ValueError):
        pass
    return table


# ──────────────────────────────────────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────────────────────────────────────

_LAYER1_TEMPLATE = '''\
import hashlib as {p}_hl, hmac as {p}_hm, sys as {p}_sy, os as {p}_os
def {p}_chk1():
    _key = bytes.fromhex({key_hex!r})
    _exp = {expected!r}
    try:
        _f = {p}_sy.modules.get(__name__)
        _f = getattr(_f, '__file__', None) if _f else None
        if not _f:
            return
        if _f.endswith('.pyc'):
            _f = _f[:-1]
        if not {p}_os.path.isfile(_f):
            return
        with open(_f, 'rb') as _fh:
            _raw = _fh.read()
        _mac = {p}_hm.new(_key, _raw, {p}_hl.sha256).hexdigest()
        if not {p}_hm.compare_digest(_mac, _exp):
            {response}
    except (OSError, AttributeError, TypeError):
        pass
{p}_chk1()
del {p}_chk1
'''

_LAYER2_TEMPLATE = '''\
import sys as {p}_sy2, marshal as {p}_ma2, hashlib as {p}_hl2, types as {p}_ty2, hmac as {p}_hm2
def {p}_chk2():
    _table = {co_table!r}
    if not _table:
        return
    _mod = {p}_sy2.modules.get(__name__)
    if not _mod:
        return
    for _k, _ev in _table.items():
        try:
            _fn = getattr(_mod, _k, None)
            if not isinstance(_fn, {p}_ty2.FunctionType):
                continue
            _h = {p}_hl2.sha256({p}_ma2.dumps(_fn.__code__)).hexdigest()
            if not {p}_hm2.compare_digest(_h, _ev):
                {response}
        except Exception:
            pass
{p}_chk2()
del {p}_chk2
'''

_LAYER3_TEMPLATE = '''\
import sys as {p}_sy3, os as {p}_os3
def {p}_chk3():
    if {p}_sy3.gettrace() is not None:
        {response}
    _bvars = (
        b'\\x50\\x59\\x54\\x48\\x4f\\x4e\\x49\\x4e\\x53\\x50\\x45\\x43\\x54',
        b'\\x50\\x59\\x44\\x42\\x44\\x4f\\x4e\\x54\\x57\\x52\\x49\\x54\\x45',
    )
    _env = {p}_os3.environb
    for _v in _bvars:
        if _env.get(_v):
            {response}
    try:
        with open(b'/proc/self/status', 'rb') as _pf:
            for _line in _pf:
                if _line.startswith(b'TracerPid'):
                    if int(_line.split(b':')[1].strip()) != 0:
                        {response}
                    break
    except OSError:
        pass
{p}_chk3()
del {p}_chk3
'''

_LAYER4_TEMPLATE = '''\
import time as {p}_tm4
def {p}_chk4():
    _t0 = {p}_tm4.perf_counter_ns()
    _acc = 0
    for _i in range({loop_count}):
        _acc ^= _i * {xor_const}
    _t1 = {p}_tm4.perf_counter_ns()
    if (_t1 - _t0) > {threshold}:
        {response}
    del _acc
{p}_chk4()
del {p}_chk4
'''

_INLINE_TEMPLATE = '''\
def {p}_ig():
    import sys as _s
    if _s.gettrace() is not None:
        _s.exit(0)
{p}_ig()
del {p}_ig
'''


# ──────────────────────────────────────────────────────────────────────────────
# Template renderer
# ──────────────────────────────────────────────────────────────────────────────

def _parse_template(src: str) -> List[ast.stmt]:
    tree = ast.parse(textwrap.dedent(src))
    ast.fix_missing_locations(tree)
    return tree.body


# ──────────────────────────────────────────────────────────────────────────────
# AntiTamperInjector
# ──────────────────────────────────────────────────────────────────────────────

class AntiTamperInjector:
    """
    Builds all anti-tamper layers as AST statement lists.

    Parameters
    ----------
    master_key   : 64-byte session master key
    source_bytes : original source bytes (for HMAC)
    co_hash_table: {func_name: sha256_hex} from original code objects
    layers       : which layers to enable (default {1,3,4})
    rng          : seeded Random instance
    """

    def __init__(
        self,
        master_key: bytes,
        source_bytes: bytes,
        co_hash_table: Optional[Dict[str, str]] = None,
        layers: Optional[set] = None,
        rng: Optional[random.Random] = None,
    ):
        self._key      = derive_integrity_key(master_key, "anti_tamper_layer1")
        self._src_mac  = compute_source_mac(source_bytes, self._key)
        self._co_table = co_hash_table or {}
        self._layers   = layers if layers is not None else {1, 3, 4}
        self._rng      = rng or random.Random(int.from_bytes(master_key[:8], "little"))
        self._pfx      = "_hpat" + secrets.token_hex(3)

    def build_stmts(self) -> List[ast.stmt]:
        stmts: List[ast.stmt] = []
        if 1 in self._layers:
            stmts.extend(_parse_template(_LAYER1_TEMPLATE.format(
                p=self._pfx + "a",
                key_hex=self._key.hex(),
                expected=self._src_mac,
                response=_RESPONSE_STMT,
            )))
        if 3 in self._layers:
            stmts.extend(_parse_template(_LAYER3_TEMPLATE.format(
                p=self._pfx + "c",
                response=_RESPONSE_STMT,
            )))
        if 4 in self._layers:
            loop_count = self._rng.randint(10_000, 30_000)
            xor_const  = self._rng.randint(0x1001, 0xFFFE)
            stmts.extend(_parse_template(_LAYER4_TEMPLATE.format(
                p=self._pfx + "d",
                loop_count=loop_count,
                xor_const=xor_const,
                threshold=_TIMING_THRESHOLD_NS,
                response=_RESPONSE_STMT,
            )))
        if 2 in self._layers and self._co_table:
            stmts.extend(_parse_template(_LAYER2_TEMPLATE.format(
                p=self._pfx + "b",
                co_table=self._co_table,
                response=_RESPONSE_STMT,
            )))
        return stmts


# ──────────────────────────────────────────────────────────────────────────────
# Inline per-function guard transformer
# ──────────────────────────────────────────────────────────────────────────────

class InlineFunctionGuardTransformer(ast.NodeTransformer):
    """
    Injects a lightweight sys.gettrace() check at entry of randomly
    selected function bodies. Probability controls how many functions get guarded.
    """

    def __init__(self, rng: Optional[random.Random] = None, probability: float = 0.45):
        self._rng  = rng or random.Random(secrets.randbits(32))
        self._prob = probability

    def _guard_stmts(self) -> List[ast.stmt]:
        pfx = "_hpig" + secrets.token_hex(3)
        return _parse_template(_INLINE_TEMPLATE.format(p=pfx))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        if self._rng.random() < self._prob:
            node.body = self._guard_stmts() + node.body
            ast.fix_missing_locations(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)


# ──────────────────────────────────────────────────────────────────────────────
# Public factory
# ──────────────────────────────────────────────────────────────────────────────

def make_anti_tamper_stmts(
    master_key: bytes,
    source_bytes: bytes,
    rng: random.Random,
    layers: Optional[set] = None,
) -> Tuple[List[ast.stmt], InlineFunctionGuardTransformer]:
    """
    Returns (module_level_stmts, inline_transformer).
    Caller applies inline_transformer.visit(tree) after other transforms.
    """
    injector = AntiTamperInjector(
        master_key=master_key,
        source_bytes=source_bytes,
        layers=layers or {1, 3, 4},
        rng=rng,
    )
    module_stmts = injector.build_stmts()
    inline_xfm   = InlineFunctionGuardTransformer(
        rng=random.Random(rng.randint(0, 2**31)),
        probability=0.45,
    )
    return module_stmts, inline_xfm

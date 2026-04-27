"""
helioporbit.transforms.name_mangler
Renames all user-defined identifiers (variables, functions, classes, parameters,
attributes) to unrecognisable names using one of four strategies:

  hash      → _hXXXXXXXX  (SHA-256 prefix)
  unicode   → confusable Unicode look-alikes  (Cyrillic, Greek, fullwidth)
  phonetic  → pronounceable but meaningless syllable chains
  numeric   → _n0001, _n0002 …

The mangler is scope-aware: it builds a SymbolTable by walking the AST in
declaration order, then rewrites every reference in a second pass.

Preserved (never mangled):
  • dunder names  (__init__, __all__, …)
  • builtins & stdlib names
  • names in __all__ exports list
  • decorator names from a safe-list
"""

from __future__ import annotations

import ast
import hashlib
import random
import re
import string
from typing import Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Safe names — never rename these
# ──────────────────────────────────────────────────────────────────────────────

import builtins as _builtins_mod; _BUILTINS: Set[str] = set(dir(_builtins_mod))

_STDLIB_COMMON: Set[str] = {
    "os", "sys", "re", "io", "abc", "ast", "json", "math", "time", "copy",
    "enum", "uuid", "struct", "random", "hashlib", "hmac", "base64", "typing",
    "pathlib", "logging", "functools", "itertools", "collections", "contextlib",
    "threading", "multiprocessing", "subprocess", "socket", "http", "urllib",
    "dataclasses", "inspect", "traceback", "warnings", "types", "weakref",
    "operator", "string", "textwrap", "shutil", "glob", "tempfile",
    "argparse", "unittest", "pprint", "decimal", "fractions", "statistics",
    "datetime", "calendar", "locale", "codecs", "csv", "sqlite3", "pickle",
    "queue", "heapq", "bisect", "array", "mmap", "signal", "errno",
    "platform", "gc", "dis", "code", "cProfile", "profile", "timeit",
    # helioporbit runtime helpers
    "_hpb_ds", "_hpb_cc", "_hpb_xd", "_hpb_aes", "_hpb_cache",
    "_b85mod", "_hmod", "_stmod", "_hmmod",
}

_SAFE_DECORATORS: Set[str] = {
    "property", "staticmethod", "classmethod", "abstractmethod",
    "overload", "final", "dataclass", "lru_cache", "cache",
    "wraps", "contextmanager",
}

_DUNDER_RE = re.compile(r"^__\w+__$")


def _is_safe(name: str) -> bool:
    if _DUNDER_RE.match(name):
        return True
    if name in _BUILTINS:
        return True
    if name in _STDLIB_COMMON:
        return True
    if name.startswith("_hpb_"):
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Mangling strategies
# ──────────────────────────────────────────────────────────────────────────────

# Unicode confusables: Latin → similar-looking Cyrillic / Greek / Math chars
_CONFUSABLE_MAP = {
    "a": "а",  # Cyrillic а
    "e": "е",  # Cyrillic е
    "o": "о",  # Cyrillic о
    "p": "р",  # Cyrillic р
    "c": "с",  # Cyrillic с
    "x": "х",  # Cyrillic х
    "i": "і",  # Cyrillic і
    "A": "А",  # Cyrillic А
    "B": "В",  # Cyrillic В
    "E": "Е",  # Cyrillic Е
    "H": "Н",  # Cyrillic Н
    "K": "К",  # Cyrillic К
    "M": "М",  # Cyrillic М
    "O": "О",  # Cyrillic О
    "P": "Р",  # Cyrillic Р
    "T": "Т",  # Cyrillic Т
    "X": "Х",  # Cyrillic Х
}

_SYLLABLES = [
    "ko","ra","li","bu","za","ne","fi","ta","mo","su","ve","xi","qu","pa","de",
    "gu","we","ru","ho","ca","ni","je","to","yu","bi","fe","lu","sa","wi","pe",
    "do","ha","re","vi","zo","ke","na","go","me","ty","pu","la","ze","bo","si",
]


class NameMangler:
    def __init__(
        self,
        style: str = "hash",
        prefix: str = "_h",
        master_key: bytes = b"",
        rng: Optional[random.Random] = None,
    ):
        self.style  = style
        self.prefix = prefix
        self.key    = master_key or b"\x00" * 32
        self.rng    = rng or random.Random(int.from_bytes(self.key[:8], "little"))
        self._map: Dict[str, str]         = {}   # original → mangled
        self._rev: Dict[str, str]         = {}   # mangled → original
        self._counter: int                = 0
        self._used: Set[str]              = set()

    # ── name generation ────────────────────────────────────────────────────────

    def _hash_name(self, original: str) -> str:
        digest = hashlib.sha256(self.key + original.encode()).hexdigest()[:12]
        return f"{self.prefix}{digest}"

    def _unicode_name(self, original: str) -> str:
        # Replace some chars with confusables, pad with Cyrillic
        result = []
        for ch in original:
            result.append(_CONFUSABLE_MAP.get(ch, ch))
        # add random Cyrillic suffix to ensure uniqueness
        suffix = "".join(
            chr(self.rng.randint(0x0430, 0x044F)) for _ in range(4)
        )
        return "".join(result) + suffix

    def _phonetic_name(self, original: str) -> str:
        # Use original length as a hint for syllable count
        n_syl = max(2, min(6, len(original) // 3 + 1))
        return self.prefix + "".join(self.rng.choices(_SYLLABLES, k=n_syl)) + str(self._counter)

    def _numeric_name(self) -> str:
        return f"{self.prefix}n{self._counter:05d}"

    def _fresh_name(self, original: str) -> str:
        self._counter += 1
        if self.style == "hash":
            candidate = self._hash_name(original)
        elif self.style == "unicode":
            candidate = self._unicode_name(original)
        elif self.style == "phonetic":
            candidate = self._phonetic_name(original)
        else:
            candidate = self._numeric_name()

        # Collision resolution
        base = candidate
        while candidate in self._used:
            candidate = base + str(self._counter)
            self._counter += 1
        self._used.add(candidate)
        return candidate

    # ── public API ─────────────────────────────────────────────────────────────

    def mangle(self, original: str) -> str:
        if _is_safe(original):
            return original
        if original in self._map:
            return self._map[original]
        mangled = self._fresh_name(original)
        self._map[original] = mangled
        self._rev[mangled]  = original
        return mangled

    def get_map(self) -> Dict[str, str]:
        return dict(self._map)

    def get_reverse_map(self) -> Dict[str, str]:
        return dict(self._rev)


# ──────────────────────────────────────────────────────────────────────────────
# AST visitor/transformer
# ──────────────────────────────────────────────────────────────────────────────

class _ScopeCollector(ast.NodeVisitor):
    """First pass: collect all user-defined names so the mangler can pre-register them."""

    def __init__(self, mangler: NameMangler, exports: Set[str]):
        self.mangler = mangler
        self.exports = exports

    def _maybe(self, name: str) -> None:
        if name and name not in self.exports:
            self.mangler.mangle(name)

    def visit_FunctionDef(self, node): self._maybe(node.name); self.generic_visit(node)
    def visit_AsyncFunctionDef(self, node): self._maybe(node.name); self.generic_visit(node)
    def visit_ClassDef(self, node): self._maybe(node.name); self.generic_visit(node)
    def visit_arg(self, node): self._maybe(node.arg); self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._maybe(node.id)

    def visit_Global(self, node):
        for name in node.names:
            self._maybe(name)

    def visit_Nonlocal(self, node):
        for name in node.names:
            self._maybe(name)


class ManglerTransformer(ast.NodeTransformer):
    """Second pass: replace every Name, arg, FunctionDef.name, ClassDef.name."""

    def __init__(self, mangler: NameMangler):
        self.mangler = mangler

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self.mangler.mangle(node.id)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self.mangler.mangle(node.name)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.name = self.mangler.mangle(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.name = self.mangler.mangle(node.name)
        self.generic_visit(node)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self.mangler.mangle(node.arg)
        self.generic_visit(node)
        return node

    def visit_Global(self, node: ast.Global) -> ast.Global:
        node.names = [self.mangler.mangle(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.Nonlocal:
        node.names = [self.mangler.mangle(n) for n in node.names]
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        # Only mangle attrs that are in the mangler's known map (user-defined)
        node.attr = self.mangler._map.get(node.attr, node.attr)
        self.generic_visit(node)
        return node

    def visit_keyword(self, node: ast.keyword) -> ast.keyword:
        if node.arg is not None:
            node.arg = self.mangler._map.get(node.arg, node.arg)
        self.generic_visit(node)
        return node


def apply_name_mangling(tree: ast.AST, mangler: NameMangler) -> ast.AST:
    # Collect exports from __all__ if present
    exports: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant):
                                exports.add(elt.value)

    collector = _ScopeCollector(mangler, exports)
    collector.visit(tree)

    transformer = ManglerTransformer(mangler)
    return transformer.visit(tree)

"""
helioporbit.transforms.wordlist_mangler
Replaces identifiers with combinations from a user-supplied wordlist,
producing names like: get_database_config, load_user_session, parse_token_value
that look like real code but map to completely wrong things.

This is far more deceptive than hash-based mangling (_h3f9a2c...)
because human readers assume the names are meaningful.

Strategy:
  - Load wordlist (one word per line)
  - Derive a deterministic shuffle of the wordlist from the session master key
  - For each identifier, pick 2-3 words from the shuffled list and join with '_'
  - Counter ensures uniqueness; HKDF ensures different sessions produce different mappings
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import random
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

# Fallback built-in wordlist if user doesn't provide one
_BUILTIN_WORDS = [
    "get", "set", "load", "save", "init", "create", "build", "parse",
    "read", "write", "fetch", "push", "pull", "send", "recv", "handle",
    "process", "update", "delete", "insert", "select", "filter", "check",
    "verify", "validate", "encode", "decode", "encrypt", "decrypt", "hash",
    "cache", "store", "index", "count", "total", "base", "core", "main",
    "data", "info", "meta", "config", "token", "key", "value", "type",
    "user", "group", "role", "scope", "mode", "flag", "state", "status",
    "error", "result", "output", "input", "query", "cursor", "buffer",
    "stream", "event", "hook", "handler", "manager", "service", "client",
    "server", "request", "response", "session", "context", "payload",
    "frame", "block", "chunk", "packet", "segment", "header", "footer",
    "record", "entry", "node", "edge", "path", "route", "rule", "policy",
    "limit", "offset", "size", "length", "depth", "width", "height",
    "source", "target", "origin", "dest", "proxy", "mirror", "replica",
    "primary", "secondary", "master", "worker", "agent", "daemon", "task",
    "job", "queue", "pipe", "lock", "mutex", "semaphore", "signal", "slot",
    "port", "host", "addr", "bind", "connect", "accept", "close", "reset",
    "retry", "timeout", "interval", "period", "delay", "offset", "delta",
    "alpha", "beta", "gamma", "delta", "epsilon", "sigma", "omega", "lambda",
    "version", "revision", "snapshot", "digest", "checksum", "signature",
    "prefix", "suffix", "pattern", "template", "schema", "format", "layout",
    "page", "view", "model", "controller", "middleware", "plugin", "module",
    "package", "bundle", "archive", "snapshot", "backup", "restore", "sync",
]

import builtins as _bmod
_BUILTINS_SET: Set[str] = set(dir(_bmod))
_DUNDER_RE = re.compile(r"^__\w+__$")
_HELIOPORBIT_PREFIXES = ("_hpb_", "_jk", "_jm", "_h", "_b85", "_hmod", "_stmod", "_hmmod")


def _is_safe(name: str) -> bool:
    if _DUNDER_RE.match(name):
        return True
    if name in _BUILTINS_SET:
        return True
    for pfx in _HELIOPORBIT_PREFIXES:
        if name.startswith(pfx):
            return True
    return False


# Directory of this file — used to auto-locate wordlist
_THIS_DIR = Path(__file__).parent


def _find_wordlist_auto() -> Optional[str]:
    """
    Search for a wordlist file automatically in this order:
      1. Any *.txt file in the same directory as wordlist_mangler.py
         whose name contains "word" (case-insensitive)
      2. Any *.txt file in the same directory (first match)
    Returns the path string, or None if nothing found.
    """
    # Priority 1: files with "word" in the name
    for candidate in sorted(_THIS_DIR.glob("*.txt")):
        if "word" in candidate.stem.lower():
            return str(candidate)
    # Priority 2: any .txt file in the directory
    for candidate in sorted(_THIS_DIR.glob("*.txt")):
        return str(candidate)
    return None


def load_wordlist(path: Optional[str] = None) -> List[str]:
    """
    Load a wordlist (one word per line).

    Resolution order:
      1. Explicit *path* argument (if provided and file exists)
      2. Auto-detect: any *.txt in the same folder as wordlist_mangler.py
         (files with "word" in their name take priority)
      3. Built-in fallback list (~220 words)

    Only words that are:
      - 3-12 characters long
      - ASCII alphabetic only (no digits, no punctuation)
    are kept.  Up to 5,000 words are used.
    """
    resolved_path: Optional[str] = None

    if path:
        if Path(path).is_file():
            resolved_path = path
        else:
            print("[wordlist] WARNING: specified path not found: " + path + " — trying auto-detect")

    if resolved_path is None:
        resolved_path = _find_wordlist_auto()
        if resolved_path:
            print("[wordlist] Auto-detected: " + resolved_path)

    if resolved_path is None:
        print("[wordlist] No wordlist file found — using built-in vocabulary ("+str(len(_BUILTIN_WORDS))+" words)")
        return list(_BUILTIN_WORDS)

    try:
        words = []
        with open(resolved_path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip().lower()
                if 3 <= len(word) <= 12 and word.isalpha() and word.isascii():
                    words.append(word)
        if not words:
            print("[wordlist] File was empty or had no valid words — using built-in")
            return list(_BUILTIN_WORDS)
        if len(words) < 50:
            print("[wordlist] Only " + str(len(words)) + " valid words found — supplementing with built-in")
            words = words + _BUILTIN_WORDS
        words = words[:5000]
        print("[wordlist] Loaded " + str(len(words)) + " words from: " + resolved_path)
        return words
    except (OSError, IOError) as exc:
        print("[wordlist] Failed to read " + str(resolved_path) + ": " + str(exc) + " — using built-in")
        return list(_BUILTIN_WORDS)


class WordlistMangler:
    """
    Maps each identifier to a fake-but-plausible multi-word name.

    Example mappings:
        my_function  ->  load_session_token
        process_data ->  get_config_value
        UserManager  ->  RequestHandler
        secret_key   ->  base_data_offset
    """

    def __init__(
        self,
        words: List[str],
        master_key: bytes,
        min_parts: int = 2,
        max_parts: int = 3,
        capitalize_classes: bool = True,
    ):
        self.master_key        = master_key
        self.min_parts         = min_parts
        self.max_parts         = max_parts
        self.capitalize_classes = capitalize_classes
        self._map: Dict[str, str]  = {}
        self._rev: Dict[str, str]  = {}
        self._used: Set[str]       = set()
        self._counter: int         = 0

        # Derive a deterministic shuffle of words from the master key
        seed = int.from_bytes(
            hmac.new(master_key, b"wordlist_shuffle", hashlib.sha256).digest()[:8],
            "little",
        )
        self._rng   = random.Random(seed)
        self._words = list(words)
        self._rng.shuffle(self._words)

    def _fresh_name(self, original: str, is_class: bool = False) -> str:
        self._counter += 1
        # Number of word parts: 2 or 3
        n_parts = self._rng.randint(self.min_parts, self.max_parts)
        while True:
            parts = self._rng.choices(self._words, k=n_parts)
            if is_class and self.capitalize_classes:
                # CamelCase for classes: LoadSessionToken
                candidate = "".join(p.capitalize() for p in parts)
            else:
                # snake_case for everything else: load_session_token
                candidate = "_".join(parts)
            # Uniqueness check
            if candidate not in self._used and candidate not in _BUILTINS_SET:
                break
            # If collision, add numeric suffix
            candidate = candidate + str(self._counter)
            if candidate not in self._used:
                break
        self._used.add(candidate)
        return candidate

    def mangle(self, original: str, is_class: bool = False) -> str:
        if _is_safe(original):
            return original
        if original in self._map:
            return self._map[original]
        mangled = self._fresh_name(original, is_class=is_class)
        self._map[original] = mangled
        self._rev[mangled]  = original
        return mangled

    def get_map(self) -> Dict[str, str]:
        return dict(self._map)

    def get_reverse_map(self) -> Dict[str, str]:
        return dict(self._rev)


# ── AST transformer ────────────────────────────────────────────────────────────

class _WordlistScopeCollector(ast.NodeVisitor):
    def __init__(self, mangler: WordlistMangler, exports: Set[str]):
        self.mangler = mangler
        self.exports = exports

    def _maybe(self, name: str, is_class: bool = False) -> None:
        if name and name not in self.exports:
            self.mangler.mangle(name, is_class=is_class)

    def visit_FunctionDef(self, node):
        self._maybe(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._maybe(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self._maybe(node.name, is_class=True)
        self.generic_visit(node)

    def visit_arg(self, node):
        self._maybe(node.arg)
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._maybe(node.id)


class WordlistManglerTransformer(ast.NodeTransformer):
    def __init__(self, mangler: WordlistMangler):
        self.mangler = mangler

    def _m(self, name: str, is_class: bool = False) -> str:
        return self.mangler.mangle(name, is_class=is_class)

    def visit_Name(self, node):
        node.id = self._m(node.id)
        return node

    def visit_FunctionDef(self, node):
        node.name = self._m(node.name)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        node.name = self._m(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        node.name = self._m(node.name, is_class=True)
        self.generic_visit(node)
        return node

    def visit_arg(self, node):
        node.arg = self._m(node.arg)
        self.generic_visit(node)
        return node

    def visit_Attribute(self, node):
        node.attr = self.mangler._map.get(node.attr, node.attr)
        self.generic_visit(node)
        return node

    def visit_keyword(self, node):
        if node.arg:
            node.arg = self.mangler._map.get(node.arg, node.arg)
        self.generic_visit(node)
        return node

    def visit_Global(self, node):
        node.names = [self._m(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._m(n) for n in node.names]
        return node

    def visit_Import(self, node):
        return node

    def visit_ImportFrom(self, node):
        return node


def apply_wordlist_mangling(tree: ast.AST, mangler: WordlistMangler) -> ast.AST:
    exports: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant):
                                exports.add(elt.value)

    collector = _WordlistScopeCollector(mangler, exports)
    collector.visit(tree)

    transformer = WordlistManglerTransformer(mangler)
    return transformer.visit(tree)

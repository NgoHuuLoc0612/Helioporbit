"""
helioporbit.transforms.anti_debug
Injects runtime anti-debugging / anti-tampering checks.

Passive mode:  environment variable checks, timing jitter
Aggressive mode: sys.gettrace(), debugger detection, checksum verification

helioporbit.transforms.junk_imports
Injects imports of real stdlib modules that are never used,
creating noise in import analysis.
"""

from __future__ import annotations

import ast
import random
import secrets
import textwrap
from typing import List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Anti-debug stubs (as source strings parsed to AST)
# ──────────────────────────────────────────────────────────────────────────────

_PASSIVE_CHECKS = [
    # Check for PYTHONINSPECT / PYTHONDONTWRITEBYTECODE environment vars
    '''
import os as _hpb_os_chk
if _hpb_os_chk.environ.get('\x50\x59\x54\x48\x4f\x4e\x49\x4e\x53\x50\x45\x43\x54'):
    raise SystemExit(0)
del _hpb_os_chk
''',
    # Timing: ensure time.time() is real (not monkey-patched to return 0)
    '''
import time as _hpb_time_chk
_hpb_t0 = _hpb_time_chk.time()
_hpb_t1 = _hpb_time_chk.time()
if _hpb_t1 < _hpb_t0:
    raise SystemExit(1)
del _hpb_t0, _hpb_t1, _hpb_time_chk
''',
]

_AGGRESSIVE_CHECKS = [
    # sys.gettrace() returns non-None when a debugger/tracer is active
    '''
import sys as _hpb_sys_chk
if _hpb_sys_chk.gettrace() is not None:
    import time as _hpb_tc; _hpb_tc.sleep(9999)
del _hpb_sys_chk
''',
    # Check for common debugger frame names in the call stack
    '''
import sys as _hpb_sys2
_hpb_fr = _hpb_sys2._getframe()
_hpb_dbg_names = {'\x70\x64\x62', '\x62\x70\x79\x74\x68\x6f\x6e', '\x70\x79\x64\x65\x76\x64'}
while _hpb_fr is not None:
    if _hpb_fr.f_code.co_filename and any(d in _hpb_fr.f_code.co_filename for d in _hpb_dbg_names):
        raise SystemExit(2)
    _hpb_fr = _hpb_fr.f_back
del _hpb_fr, _hpb_sys2, _hpb_dbg_names
''',
    # settrace tamper detection: install a trace that detects removal
    '''
import sys as _hpb_sys3, ctypes as _hpb_ct
try:
    _hpb_ct.pythonapi.PyEval_SetTrace
except AttributeError:
    pass
del _hpb_sys3, _hpb_ct
''',
]


def _parse_check(src: str) -> List[ast.stmt]:
    tree = ast.parse(textwrap.dedent(src))
    return tree.body


def make_anti_debug_stmts(mode: str, rng: random.Random) -> List[ast.stmt]:
    """Return a list of AST statements implementing anti-debug checks."""
    stmts: List[ast.stmt] = []

    if mode in ("passive", "aggressive"):
        check = rng.choice(_PASSIVE_CHECKS)
        stmts.extend(_parse_check(check))

    if mode == "aggressive":
        check = rng.choice(_AGGRESSIVE_CHECKS)
        stmts.extend(_parse_check(check))

    return stmts


# ──────────────────────────────────────────────────────────────────────────────
# Junk import injector
# ──────────────────────────────────────────────────────────────────────────────

_JUNK_STDLIB_MODULES = [
    "calendar", "colorsys", "configparser", "cProfile", "csv", "curses",
    "decimal", "difflib", "email", "encodings", "enum", "errno",
    "filecmp", "fnmatch", "fractions", "ftplib", "functools",
    "getpass", "gettext", "glob", "grp", "gzip",
    "heapq", "html", "http",
    "imaplib", "imghdr", "inspect", "ipaddress",
    "keyword", "linecache", "locale", "lzma",
    "mailbox", "mimetypes",
    "netrc", "nntplib", "ntpath", "numbers",
    "opcode", "optparse",
    "pdb", "pickletools", "pkgutil", "plistlib", "poplib", "posix",
    "pprint", "profile", "pstats", "pty", "pwd",
    "queue", "quopri",
    "readline", "rlcompleter",
    "sched", "selectors", "shelve", "shlex",
    "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
    "spwd", "sqlite3", "sre_compile", "sre_constants", "sre_parse",
    "stat", "statistics", "string", "stringprep",
    "tarfile", "telnetlib", "termios", "test", "textwrap",
    "token", "tokenize", "tomllib", "trace", "tracemalloc",
    "turtle", "turtledemo",
    "uu",
    "wave", "webbrowser",
    "xdrlib", "xml", "xmlrpc",
    "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo",
]


def make_junk_import_stmts(count: int, rng: random.Random) -> List[ast.stmt]:
    """Return *count* import statements for unused stdlib modules with aliased names."""
    chosen  = rng.sample(_JUNK_STDLIB_MODULES, min(count, len(_JUNK_STDLIB_MODULES)))
    stmts: List[ast.stmt] = []
    for mod in chosen:
        alias_name = "_jm" + secrets.token_hex(4)
        node = ast.Import(names=[ast.alias(name=mod, asname=alias_name)])
        ast.fix_missing_locations(node)
        stmts.append(node)
    return stmts


# ──────────────────────────────────────────────────────────────────────────────
# Builtin renamer
# ──────────────────────────────────────────────────────────────────────────────

_RENAMEABLE_BUILTINS = [
    "len", "range", "list", "dict", "set", "tuple", "str", "int", "float",
    "bool", "bytes", "bytearray", "type", "isinstance", "issubclass",
    "hasattr", "getattr", "setattr", "delattr", "callable", "iter", "next",
    "enumerate", "zip", "map", "filter", "sorted", "reversed", "sum",
    "min", "max", "abs", "round", "pow", "divmod", "hex", "oct", "bin",
    "repr", "hash", "id", "chr", "ord", "format", "vars", "dir",
    "any", "all", "open", "print", "input",
]


class BuiltinRenamer(ast.NodeTransformer):
    """
    Assigns builtins to local aliases with obfuscated names.
    Injects at module top-level:
        _hb_len = len
        _hb_range = range
        ...
    Then replaces usages in function bodies.
    """

    def __init__(self, rng: Optional[random.Random] = None, probability: float = 0.7):
        self.rng         = rng or random.Random()
        self.probability = probability
        self._alias: dict[str, str] = {}

    def _choose_builtins(self, tree: ast.Module) -> None:
        for b in _RENAMEABLE_BUILTINS:
            if self.rng.random() < self.probability:
                self._alias[b] = "_hb" + secrets.token_hex(5)

    def apply(self, tree: ast.Module) -> ast.Module:
        self._choose_builtins(tree)

        # Inject alias assignments at module top (after imports)
        alias_stmts = []
        for original, alias in self._alias.items():
            stmt = ast.Assign(
                targets=[ast.Name(id=alias, ctx=ast.Store())],
                value=ast.Name(id=original, ctx=ast.Load()),
                lineno=1, col_offset=0,
            )
            ast.fix_missing_locations(stmt)
            alias_stmts.append(stmt)

        # Find insertion point (after last import)
        insert_at = 0
        for i, node in enumerate(tree.body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_at = i + 1

        tree.body = tree.body[:insert_at] + alias_stmts + tree.body[insert_at:]

        # Rewrite usages
        return self.visit(tree)

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if isinstance(node.ctx, ast.Load) and node.id in self._alias:
            node.id = self._alias[node.id]
        return node

    def visit_Import(self, node): return node
    def visit_ImportFrom(self, node): return node


# ──────────────────────────────────────────────────────────────────────────────
# Lambda converter: def f(x): return expr  →  f = lambda x: expr
# ──────────────────────────────────────────────────────────────────────────────

class LambdaConverter(ast.NodeTransformer):
    """
    Converts simple single-expression functions to lambda assignments.
    Adds cognitive load: readers must track lambda bindings.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.stmt:
        # Only convert trivially simple functions: single return statement
        if (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Return)
            and node.body[0].value is not None
            and not node.decorator_list
            and not node.returns  # no type annotation
        ):
            lam = ast.Lambda(args=node.args, body=node.body[0].value)
            assign = ast.Assign(
                targets=[ast.Name(id=node.name, ctx=ast.Store())],
                value=lam,
                lineno=node.lineno,
                col_offset=node.col_offset,
            )
            ast.fix_missing_locations(assign)
            return assign
        self.generic_visit(node)
        return node

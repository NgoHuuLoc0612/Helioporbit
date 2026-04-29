"""
helioporbit.transforms.secret_fragmenter
Splits string/bytes constants that look like secrets into N fragments
stored in separate variables, reconstructed at runtime via a join call.

Before:
    API_KEY = "sk-prod-a1b2c3d4e5f6-secret"

After (conceptually):
    _f0 = _hpb_ds(...)   # "sk-prod"
    _f1 = _hpb_ds(...)   # "-a1b2c3"
    _f2 = _hpb_ds(...)   # "d4e5f6-"
    _f3 = _hpb_ds(...)   # "secret"
    API_KEY = _f0 + _f1 + _f2 + _f3

Each fragment is independently encrypted with its own key.
The fragmentation happens BEFORE the main StringEncryptor pass,
so each fragment gets separately encrypted with a fresh per-fragment key.

Additionally, fragments are stored out of order and reassembled via
an index table:
    _frags = [_f2, _f0, _f3, _f1]
    API_KEY = "".join(_frags[i] for i in [1, 3, 0, 2])
"""

from __future__ import annotations

import ast
import math
import random
import re
import secrets
from typing import List, Optional, Tuple

# Heuristic: which string values look like "secrets"?
_SECRET_PATTERNS = [
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}$"),       # base64-ish
    re.compile(r"[0-9a-f]{16,}$"),                    # hex strings
    re.compile(r"sk[-_][A-Za-z0-9]{8,}"),             # API keys
    re.compile(r"[A-Za-z0-9]{32,}"),                  # long random strings
    re.compile(r"https?://\S+"),                       # URLs with credentials
    re.compile(r"\w+://\w+:\S+@\S+"),                 # connection strings
    re.compile(r"-----BEGIN"),                         # PEM keys
    re.compile(r"[A-Z_]{3,}KEY\b"),                   # KEY variables
    re.compile(r"[A-Z_]{3,}SECRET\b"),                # SECRET variables
    re.compile(r"[A-Z_]{3,}TOKEN\b"),                 # TOKEN variables
    re.compile(r"[A-Z_]{3,}PASSWORD\b"),              # PASSWORD variables
]

_MIN_FRAGMENT_LEN = 3
_MAX_FRAGMENTS    = 8


def _looks_like_secret(s: str) -> bool:
    """Heuristic: is this string likely a secret that should be fragmented?"""
    if len(s) < 8:
        return False
    # Any string >= 16 chars containing mixed case/digits is likely sensitive
    if len(s) >= 16:
        has_upper  = any(c.isupper() for c in s)
        has_lower  = any(c.islower() for c in s)
        has_digit  = any(c.isdigit() for c in s)
        has_special= any(not c.isalnum() for c in s)
        if (has_upper or has_digit or has_special) and has_lower:
            return True
    for pat in _SECRET_PATTERNS:
        if pat.search(s):
            return True
    return False


def _split_string(s: str, n_parts: int, rng: random.Random) -> List[str]:
    """Split string into n_parts of roughly equal size (slightly randomized)."""
    if n_parts <= 1 or len(s) < n_parts * _MIN_FRAGMENT_LEN:
        return [s]

    # Random split points
    step = len(s) / n_parts
    cuts = sorted(set(
        max(1, min(len(s) - 1, round(step * i + rng.uniform(-step * 0.3, step * 0.3))))
        for i in range(1, n_parts)
    ))
    cuts = [0] + cuts + [len(s)]
    return [s[cuts[i]:cuts[i + 1]] for i in range(len(cuts) - 1) if cuts[i] < cuts[i + 1]]


class SecretFragmenter(ast.NodeTransformer):
    """
    Finds string constants that look like secrets and replaces them with
    fragmented, out-of-order assembly expressions.

    The actual encryption of each fragment is left to the StringEncryptor
    pass that runs after this transform.
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        min_fragments: int = 3,
        max_fragments: int = _MAX_FRAGMENTS,
        force_all: bool = False,     # fragment ALL strings, not just secret-looking ones
        min_length: int = 8,
    ):
        self.rng          = rng or random.Random()
        self.min_fragments = min_fragments
        self.max_fragments = max_fragments
        self.force_all    = force_all
        self.min_length   = min_length
        self._stmts_to_prepend: List[Tuple[int, List[ast.stmt]]] = []
        self._counter     = 0

    def _next_frag_name(self) -> str:
        self._counter += 1
        return "_hfr" + secrets.token_hex(5) + str(self._counter)

    def _make_fragment_expr(self, fragments: List[str], rng: random.Random) -> Tuple[ast.expr, List[ast.stmt]]:
        """
        Create a shuffled fragment assembly expression.
        Returns (assembly_expr, [pre_stmts_to_hoist]).

        The expression looks like:
            _hfr1 + _hfr3 + _hfr0 + _hfr2
        where the _hfrN variables are assigned in shuffled order above.

        Each fragment variable holds a substring — the StringEncryptor
        will later encrypt each one independently.
        """
        n = len(fragments)
        names = [self._next_frag_name() for _ in range(n)]

        # Shuffle storage order (index -> fragment)
        order = list(range(n))
        rng.shuffle(order)

        # Build pre-statements: _hfrX = "fragment" (in shuffled order)
        pre_stmts = []
        for shuffled_pos, orig_idx in enumerate(order):
            var_name = names[orig_idx]
            assign   = ast.Assign(
                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                value=ast.Constant(value=fragments[orig_idx]),
                lineno=1, col_offset=0,
            )
            ast.fix_missing_locations(assign)
            pre_stmts.append(assign)

        # Build assembly: names[0] + names[1] + ... in ORIGINAL order
        expr: ast.expr = ast.Name(id=names[0], ctx=ast.Load())
        for name in names[1:]:
            expr = ast.BinOp(
                left=expr,
                op=ast.Add(),
                right=ast.Name(id=name, ctx=ast.Load()),
            )
        ast.fix_missing_locations(expr)
        return expr, pre_stmts

    def _should_fragment(self, s: str) -> bool:
        if len(s) < self.min_length:
            return False
        if self.force_all:
            return True
        return _looks_like_secret(s)

    def visit_Assign(self, node: ast.Assign) -> List[ast.stmt]:
        """
        Handle top-level assignments: API_KEY = "secret"
        Hoists fragment variables immediately before the assignment.
        """
        # First visit children
        self.generic_visit(node)

        if not (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and self._should_fragment(node.value.value)
        ):
            return [node]

        s      = node.value.value
        n_frag = self.rng.randint(self.min_fragments, min(self.max_fragments, max(self.min_fragments, len(s) // 3)))
        frags  = _split_string(s, n_frag, self.rng)

        if len(frags) < 2:
            return [node]

        expr, pre_stmts = self._make_fragment_expr(frags, self.rng)
        node.value = expr
        ast.fix_missing_locations(node)
        return pre_stmts + [node]

    def visit_Module(self, node: ast.Module) -> ast.Module:
        new_body: List[ast.stmt] = []
        for stmt in node.body:
            result = self.visit(stmt)
            if isinstance(result, list):
                new_body.extend(result)
            elif result is not None:
                new_body.append(result)
        node.body = new_body
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        new_body: List[ast.stmt] = []
        for stmt in node.body:
            result = self.visit(stmt)
            if isinstance(result, list):
                new_body.extend(result)
            elif result is not None:
                new_body.append(result)
        node.body = new_body
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self.visit_FunctionDef(node)  # type: ignore

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        new_body: List[ast.stmt] = []
        for stmt in node.body:
            result = self.visit(stmt)
            if isinstance(result, list):
                new_body.extend(result)
            elif result is not None:
                new_body.append(result)
        node.body = new_body
        return node

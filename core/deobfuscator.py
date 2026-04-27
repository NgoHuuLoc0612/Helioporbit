"""
helioporbit.core.deobfuscator
Reverses a Helioporbit-obfuscated source file back to readable Python
using the encrypted session artefact (.hpb).

Reversal steps (in inverse pipeline order):
  1.  Load & decrypt session  (PBKDF2 + ChaCha20-Poly1305)
  2.  Parse obfuscated source → AST
  3.  Remove injected dead code & junk assignments
  4.  Reverse control-flow flattening (reconstruct while-switch → original body)
  5.  Reverse builtin aliases
  6.  Reverse name mangling (mangled → original)
  7.  Reverse integer encoding (evaluate constant-folded expressions)
  8.  Reverse string encryption (call _hpb_ds(...) → string literal)
  9.  Remove bootstrap stmts, junk imports, anti-debug stubs
  10. Restore annotations from session metadata (best-effort)
  11. ast.unparse → clean source
"""

from __future__ import annotations

import ast
import operator
import random
from pathlib import Path
from typing import Any, Dict, Optional, Set

from helioporbit.core.session import ObfuscationSession
from helioporbit.crypto.primitives import (
    chacha20_encrypt,
    aes_ctr_decrypt,
    xor_multi_decrypt,
    hkdf,
)


# ──────────────────────────────────────────────────────────────────────────────
# Constant expression evaluator (safe subset)
# ──────────────────────────────────────────────────────────────────────────────

_BINOP_MAP = {
    ast.Add:    operator.add,
    ast.Sub:    operator.sub,
    ast.Mult:   operator.mul,
    ast.Div:    operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod:    operator.mod,
    ast.Pow:    operator.pow,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
    ast.BitOr:  operator.or_,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}

_UNOP_MAP = {
    ast.USub:   operator.neg,
    ast.UAdd:   operator.pos,
    ast.Invert: operator.invert,
    ast.Not:    operator.not_,
}


_CMP_MAP = {
    ast.Eq:    lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt:    lambda a, b: a < b,
    ast.LtE:   lambda a, b: a <= b,
    ast.Gt:    lambda a, b: a > b,
    ast.GtE:   lambda a, b: a >= b,
}

def _safe_eval_expr(node: ast.expr) -> Any:
    """
    Recursively evaluate a constant arithmetic/comparison expression.
    Raises ValueError if the expression is not purely constant.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        fn = _BINOP_MAP.get(type(node.op))
        if fn is None:
            raise ValueError(f"Unsupported binary op: {node.op}")
        lv = _safe_eval_expr(node.left)
        rv = _safe_eval_expr(node.right)
        if isinstance(lv, int) and isinstance(rv, int):
            return fn(lv, rv)
        raise ValueError("Non-integer operands")
    if isinstance(node, ast.UnaryOp):
        fn = _UNOP_MAP.get(type(node.op))
        if fn is None:
            raise ValueError(f"Unsupported unary op: {node.op}")
        return fn(_safe_eval_expr(node.operand))
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        fn = _CMP_MAP.get(type(node.ops[0]))
        if fn is None:
            raise ValueError(f"Unsupported compare op: {node.ops[0]}")
        lv = _safe_eval_expr(node.left)
        rv = _safe_eval_expr(node.comparators[0])
        return fn(lv, rv)
    if isinstance(node, ast.BoolOp):
        vals = [_safe_eval_expr(v) for v in node.values]
        if isinstance(node.op, ast.And):
            result = vals[0]
            for v in vals[1:]: result = result and v
            return result
        else:
            result = vals[0]
            for v in vals[1:]: result = result or v
            return result
    raise ValueError(f"Cannot evaluate node type: {type(node).__name__}")


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 – String decryptor (AST-level)
# ──────────────────────────────────────────────────────────────────────────────

import base64


def _b85dec(s: str) -> bytes:
    return base64.b85decode(s)


def _decrypt_string(sid: str, algo_id: int, ct_b85: str, key_b85: str, nonce_b85: str) -> str:
    ct    = _b85dec(ct_b85)
    key   = _b85dec(key_b85)
    nonce = _b85dec(nonce_b85)

    if algo_id == 0:   # ChaCha20
        plain = chacha20_encrypt(key, nonce, ct, counter=1)
    elif algo_id == 1: # AES-CTR
        plain = aes_ctr_decrypt(key[:16], nonce[:16].ljust(16, b"\x00"), ct)
    else:              # XOR multi
        plain = xor_multi_decrypt(key, ct)

    return plain.decode("utf-8", errors="replace")


class _StringRestorer(ast.NodeTransformer):
    """Replace _hpb_ds(sid, algo, ct, key, nonce) calls with string literals."""

    def visit_Call(self, node: ast.Call) -> ast.expr:
        self.generic_visit(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "_hpb_ds"
            and len(node.args) == 5
            and all(isinstance(a, ast.Constant) for a in node.args)
        ):
            try:
                sid     = node.args[0].value
                algo_id = node.args[1].value
                ct_b85  = node.args[2].value
                key_b85 = node.args[3].value
                nonce_b85 = node.args[4].value
                original = _decrypt_string(sid, algo_id, ct_b85, key_b85, nonce_b85)
                return ast.Constant(value=original)
            except Exception:
                return node
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Step 2 – Integer constant folder
# ──────────────────────────────────────────────────────────────────────────────

class _IntegerFolder(ast.NodeTransformer):
    """Fold constant arithmetic back to plain integer literals."""

    def visit_BinOp(self, node: ast.BinOp) -> ast.expr:
        self.generic_visit(node)
        try:
            v = _safe_eval_expr(node)
            if isinstance(v, int) and abs(v) < 2**32:
                new_node = ast.Constant(value=v)
                ast.copy_location(new_node, node)
                return new_node
        except (ValueError, OverflowError, ZeroDivisionError):
            pass
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.expr:
        self.generic_visit(node)
        try:
            v = _safe_eval_expr(node)
            if isinstance(v, int) and abs(v) < 2**32:
                new_node = ast.Constant(value=v)
                ast.copy_location(new_node, node)
                return new_node
        except (ValueError, OverflowError):
            pass
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Step 3 – Name de-mangler
# ──────────────────────────────────────────────────────────────────────────────

class _NameDemangler(ast.NodeTransformer):
    def __init__(self, reverse_map: Dict[str, str]):
        self.rev = reverse_map

    def _unmangle(self, name: str) -> str:
        return self.rev.get(name, name)

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = self._unmangle(node.id)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self._unmangle(node.name)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.name = self._unmangle(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.name = self._unmangle(node.name)
        self.generic_visit(node)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._unmangle(node.arg)
        self.generic_visit(node)
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        node.attr = self._unmangle(node.attr)
        self.generic_visit(node)
        return node

    def visit_keyword(self, node: ast.keyword) -> ast.keyword:
        if node.arg:
            node.arg = self._unmangle(node.arg)
        self.generic_visit(node)
        return node

    def visit_Global(self, node: ast.Global) -> ast.Global:
        node.names = [self._unmangle(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.Nonlocal:
        node.names = [self._unmangle(n) for n in node.names]
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Step 4 – Junk / bootstrap / anti-debug remover
# ──────────────────────────────────────────────────────────────────────────────

_BOOTSTRAP_NAMES = {
    "_hpb_cc", "_hpb_xd", "_hpb_aes", "_hpb_ds", "_hpb_cache",
    "_b85mod", "_hmod", "_stmod", "_hmmod",
}

_ANTIDEBUG_SENTINEL_NAMES = {
    "_hpb_os_chk", "_hpb_time_chk", "_hpb_sys_chk",
    "_hpb_sys2", "_hpb_sys3", "_hpb_ct",
    "_hpb_fr", "_hpb_dbg_names", "_hpb_t0", "_hpb_t1",
}

# CFF internal variables (cleaned up AFTER CFF reversal only — not in pre-CFF junk removal)
_CFF_INTERNAL_NAMES = set()  # populated post-CFF pass

_JUNK_VAR_PREFIXES = ("_jk", "_jm")
# Broader anti-debug prefix: any _hpb_* name that is NOT a bootstrap function
_ANTIDEBUG_PREFIXES = ("_hpb_t", "_hpb_fr", "_hpb_os", "_hpb_sys", "_hpb_ct", "_hpb_dbg")


def _is_junk_name(name: str) -> bool:
    if name in _BOOTSTRAP_NAMES or name in _ANTIDEBUG_SENTINEL_NAMES:
        return True
    # _hpb_st and _hpb_rv are handled by _lift_hpb_rv_return post-CFF
    for pfx in _JUNK_VAR_PREFIXES:
        if name.startswith(pfx):
            return True
    for pfx in _ANTIDEBUG_PREFIXES:
        if name.startswith(pfx):
            return True
    return False


def _stmt_references_only_junk(stmt: ast.stmt) -> bool:
    """Return True if every Name in stmt references a junk/sentinel variable."""
    names = [n.id for n in ast.walk(stmt) if isinstance(n, ast.Name)]
    return bool(names) and all(_is_junk_name(n) for n in names)


def _is_opaque_predicate_if(node: ast.If) -> bool:
    """
    Detect if-False / if-True dead code injected by DeadCodeInjector.
    Heuristic: the condition is a constant bool or purely constant arithmetic.
    """
    try:
        val = _safe_eval_expr(node.test)
        return isinstance(val, (bool, int))
    except (ValueError, Exception):
        return False


def _is_junk_assign(node: ast.stmt) -> bool:
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and _is_junk_name(t.id):
                return True
    return False


def _is_bootstrap_def(node: ast.stmt) -> bool:
    """Detect bootstrap function definitions / imports."""
    if isinstance(node, ast.FunctionDef) and node.name in _BOOTSTRAP_NAMES:
        return True
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname and _is_junk_name(alias.asname):
                return True
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in _BOOTSTRAP_NAMES:
                return True
    return False


def _clean_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Remove bootstrap, junk assigns, dead if-False blocks, fake loops, anti-debug."""
    result = []
    for stmt in stmts:
        if _is_bootstrap_def(stmt):
            continue
        if _is_junk_assign(stmt):
            continue

        # Delete nodes referencing only sentinel vars
        if isinstance(stmt, ast.Delete):
            targets = [t for t in stmt.targets if not (isinstance(t, ast.Name) and _is_junk_name(t.id))]
            if not targets:
                continue  # all targets are junk — drop entire del
            stmt.targets = targets

        # If blocks: check opaque predicate OR anti-debug sentinel reference
        if isinstance(stmt, ast.If):
            # Pure constant-foldable predicate
            try:
                val = _safe_eval_expr(stmt.test)
                if not val:
                    continue  # if-False → dead code
                else:
                    result.extend(_clean_stmts(stmt.body))
                    continue
            except Exception:
                pass
            # Anti-debug: if block whose test only references sentinel names
            if _stmt_references_only_junk(stmt.test):
                continue

        if isinstance(stmt, ast.For):
            # Detect "for _ in range(0):" — fake loop
            if (
                isinstance(stmt.target, ast.Name)
                and stmt.target.id == "_"
                and isinstance(stmt.iter, ast.Call)
                and isinstance(stmt.iter.func, ast.Name)
                and stmt.iter.func.id == "range"
                and len(stmt.iter.args) == 1
            ):
                try:
                    n = _safe_eval_expr(stmt.iter.args[0])
                    if n == 0:
                        continue
                except Exception:
                    pass

        if isinstance(stmt, ast.Assert):
            # Remove always-true asserts with hex message (junk asserts)
            try:
                val = _safe_eval_expr(stmt.test)
                if val and isinstance(stmt.msg, ast.Constant) and isinstance(stmt.msg.value, str):
                    if len(stmt.msg.value) == 8:  # token_hex(4) = 8 chars
                        continue
            except Exception:
                pass

        # Assign/Expr that only touches sentinel names
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.Expr)):
            if _stmt_references_only_junk(stmt):
                continue

        # While loop whose test is purely sentinel references → anti-debug loop
        if isinstance(stmt, ast.While):
            if _stmt_references_only_junk(stmt.test):
                continue

        result.append(stmt)
    return result


def _lift_hpb_rv_return(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """
    Post-CFF cleanup:
      • _hpb_rv = <expr>  → remove assignment, substitute into 'return _hpb_rv'
      • _hpb_st = <const> → drop (leftover state variable)
      • return _hpb_rv    → return <expr> (using last assigned value)
    Works recursively over nested statement blocks.
    """
    # Pass 1: collect _hpb_rv assignments
    rv_values: dict[str, ast.expr] = {}
    for stmt in stmts:
        if (isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "_hpb_rv"):
            rv_values["_hpb_rv"] = stmt.value

    result = []
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            tgt = stmt.targets[0] if len(stmt.targets) == 1 else None
            if isinstance(tgt, ast.Name):
                if tgt.id == "_hpb_rv":
                    continue  # swallowed — value substituted into return
                # NOTE: do NOT drop _hpb_st here — CFFReverter needs it
        if (isinstance(stmt, ast.Return)
                and isinstance(stmt.value, ast.Name)
                and stmt.value.id == "_hpb_rv"):
            if "_hpb_rv" in rv_values:
                result.append(ast.Return(value=rv_values["_hpb_rv"]))
                ast.fix_missing_locations(result[-1])
            else:
                result.append(stmt)  # keep as-is if we couldn't trace the value
            continue
        # Recurse into nested bodies
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stmt.body = _lift_hpb_rv_return(stmt.body)
        elif isinstance(stmt, ast.If):
            stmt.body   = _lift_hpb_rv_return(stmt.body)
            stmt.orelse = _lift_hpb_rv_return(stmt.orelse) if stmt.orelse else []
        elif isinstance(stmt, ast.For):
            stmt.body   = _lift_hpb_rv_return(stmt.body)
        elif isinstance(stmt, ast.While):
            stmt.body   = _lift_hpb_rv_return(stmt.body)
        result.append(stmt)
    return result


class _JunkRemover(ast.NodeTransformer):
    def _clean(self, stmts: list[ast.stmt]) -> list[ast.stmt]:
        cleaned = _clean_stmts(stmts)
        return [self.visit(s) for s in cleaned]

    def visit_Module(self, node: ast.Module) -> ast.Module:
        node.body = self._clean(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.body = self._clean(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.body = self._clean(node.body)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.body = self._clean(node.body)
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        node.body   = self._clean(node.body)
        node.orelse = self._clean(node.orelse) if node.orelse else []
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        node.body   = self._clean(node.body)
        node.orelse = self._clean(node.orelse) if node.orelse else []
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        node.body   = self._clean(node.body)
        node.orelse = self._clean(node.orelse) if node.orelse else []
        return node

    def visit_Try(self, node: ast.Try) -> ast.Try:
        node.body      = self._clean(node.body)
        node.finalbody = self._clean(node.finalbody) if node.finalbody else []
        for h in node.handlers:
            h.body = self._clean(h.body)
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Step 5 – CFF reversal (while-switch → original sequence)
# ──────────────────────────────────────────────────────────────────────────────

_STATE_VAR = "_hpb_st"


def _extract_state_value(node: ast.expr) -> Optional[int]:
    """Extract the integer state value from an XOR-obfuscated expression."""
    try:
        v = _safe_eval_expr(node)
        if isinstance(v, int):
            return v
    except Exception:
        pass
    return None


def _parse_cff_while(while_node: ast.While) -> Optional[list[ast.stmt]]:
    """
    Attempt to reverse a CFF while-True / if-elif chain back to
    the original sequential block order.
    Returns the reconstructed statement list, or None if not recognisable.
    """
    if not (isinstance(while_node.test, ast.Constant) and while_node.test.value is True):
        return None
    if len(while_node.body) != 1 or not isinstance(while_node.body[0], ast.If):
        return None

    # Collect all branches: {state_id: [stmts]}
    branches: Dict[int, list[ast.stmt]] = {}
    exit_ids: Set[int] = set()

    def _collect(if_node: ast.If) -> None:
        if not isinstance(if_node, ast.If):
            return
        state_id = _extract_state_value(if_node.test.comparators[0]) if (
            isinstance(if_node.test, ast.Compare)
            and isinstance(if_node.test.left, ast.Name)
            and if_node.test.left.id == _STATE_VAR
            and len(if_node.test.ops) == 1
            and isinstance(if_node.test.ops[0], ast.Eq)
            and len(if_node.test.comparators) == 1
        ) else None

        if state_id is None:
            return

        body = if_node.body
        # Detect exit branch (just a Break)
        if len(body) == 1 and isinstance(body[0], ast.Break):
            exit_ids.add(state_id)
        else:
            stmts = list(body)
            next_state = None
            # Strip trailing Break FIRST (return-converted blocks end with Break)
            if stmts and isinstance(stmts[-1], ast.Break):
                stmts = stmts[:-1]
            # Then strip trailing state assignment
            if stmts and isinstance(stmts[-1], ast.Assign):
                last = stmts[-1]
                if (len(last.targets) == 1
                        and isinstance(last.targets[0], ast.Name)
                        and last.targets[0].id == _STATE_VAR):
                    next_state = _extract_state_value(last.value)
                    stmts = stmts[:-1]
            branches[state_id] = (stmts, next_state)

        if if_node.orelse:
            for child in if_node.orelse:
                if isinstance(child, ast.If):
                    _collect(child)

    _collect(while_node.body[0])

    if not branches:
        return None

    # Reconstruct order by following next_state chain from entry
    # Entry = the state_id referenced in the init assignment (not in any next_state)
    all_next = {v[1] for v in branches.values() if v[1] is not None}
    entries  = [sid for sid in branches if sid not in all_next and sid not in exit_ids]

    if not entries:
        # Fallback: just concatenate in dict-insertion order
        result = []
        for sid, (stmts, _) in branches.items():
            result.extend(stmts)
        return result if result else None

    ordered: list[ast.stmt] = []
    visited: Set[int]       = set()
    current = entries[0]

    while current is not None and current not in visited and current in branches:
        visited.add(current)
        stmts, nxt = branches[current]
        ordered.extend(stmts)
        current = nxt

    return ordered if ordered else None


class _CFFReverter(ast.NodeTransformer):
    """
    Scan function bodies for while-True/if-elif CFF patterns and reconstruct
    the original linear statement sequence.
    """

    def _try_revert_cff(self, stmts: list[ast.stmt]) -> list[ast.stmt]:
        """
        Detect the pattern:
            _hpb_st = <expr>
            while True:
                if _hpb_st == ...: ...
                elif ...
        and replace with the reconstructed linear body.
        """
        if len(stmts) < 2:
            return stmts

        result: list[ast.stmt] = []
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            # Detect init assign: _hpb_st = <const>
            if (
                i + 1 < len(stmts)
                and isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == _STATE_VAR
                and isinstance(stmts[i + 1], ast.While)
            ):
                while_node = stmts[i + 1]
                reverted = _parse_cff_while(while_node)
                if reverted is not None:
                    # Keep _hpb_rv = ... as-is: _PostCFFCleaner will substitute
                    # them into the trailing 'return _hpb_rv' after this phase.
                    result.extend(reverted)
                    i += 2
                    continue
            result.append(stmt)
            i += 1
        return result

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        node.body = self._try_revert_cff(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        self.generic_visit(node)
        node.body = self._try_revert_cff(node.body)
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Step 6 – Builtin alias reverter
# ──────────────────────────────────────────────────────────────────────────────

class _BuiltinAliasReverter(ast.NodeTransformer):
    """
    Detect  _hbXXXXX = len  (builtin alias) assignments and replace
    all usages with the original builtin name.
    """

    def __init__(self):
        self._alias_to_builtin: Dict[str, str] = {}

    # Real Python builtin names to recognise
    _KNOWN_BUILTINS = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))

    def collect(self, tree: ast.Module) -> None:
        import builtins as _bmod
        known = set(dir(_bmod))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.startswith("_hb")
                and isinstance(node.value, ast.Name)
                and node.value.id in known   # RHS must be a real builtin
            ):
                alias   = node.targets[0].id
                builtin = node.value.id
                self._alias_to_builtin[alias] = builtin

    def apply(self, tree: ast.Module) -> ast.Module:
        self.collect(tree)
        # Remove alias assignments
        tree.body = [
            s for s in tree.body
            if not (
                isinstance(s, ast.Assign)
                and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and s.targets[0].id in self._alias_to_builtin
            )
        ]
        return self.visit(tree)

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if isinstance(node.ctx, ast.Load) and node.id in self._alias_to_builtin:
            node.id = self._alias_to_builtin[node.id]
        return node



# ──────────────────────────────────────────────────────────────────────────────
# Post-CFF cleaner: remove _hpb_st / _hpb_rv leftovers after CFF reversal
# ──────────────────────────────────────────────────────────────────────────────

class _PostCFFCleaner(ast.NodeTransformer):
    """
    After CFFReverter has reconstructed linear statement sequences,
    strip any remaining _hpb_st / _hpb_rv scaffolding.
    Also converts  'return _hpb_rv'  using the last seen _hpb_rv assignment.
    """

    def _clean_body(self, stmts: list[ast.stmt]) -> list[ast.stmt]:
        # Collect rv assignments
        rv_values: dict = {}
        for stmt in stmts:
            if (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == "_hpb_rv"):
                rv_values["_hpb_rv"] = stmt.value

        result = []
        for stmt in stmts:
            # Drop _hpb_st = ... and _hpb_rv = ...
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                tgt = stmt.targets[0]
                if isinstance(tgt, ast.Name) and tgt.id in ("_hpb_st", "_hpb_rv"):
                    continue

            # Substitute return _hpb_rv → return <expr>
            if (isinstance(stmt, ast.Return)
                    and isinstance(stmt.value, ast.Name)
                    and stmt.value.id == "_hpb_rv"
                    and "_hpb_rv" in rv_values):
                new_ret = ast.Return(value=rv_values["_hpb_rv"])
                ast.fix_missing_locations(new_ret)
                result.append(new_ret)
                continue

            result.append(stmt)
        return result

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        node.body = self._clean_body(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.generic_visit(node)
        node.body = self._clean_body(node.body)
        return node

    def visit_Module(self, node: ast.Module):
        self.generic_visit(node)
        node.body = self._clean_body(node.body)
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Main Deobfuscator
# ──────────────────────────────────────────────────────────────────────────────

class Deobfuscator:
    """
    Reverse a Helioporbit-obfuscated file using its session artefact.

    Usage::

        from helioporbit import Deobfuscator

        deobf = Deobfuscator()
        source = deobf.deobfuscate_file(
            "mymodule.hpo.py",
            session_path="session_abc12345.hpb",
            session_password="s3cr3t",
        )
        print(source)
    """

    def deobfuscate_source(
        self,
        obf_source: str,
        session_path: str,
        session_password: str,
    ) -> str:
        session = ObfuscationSession.load_encrypted(session_path, session_password)
        return self._run_reversal(obf_source, session)

    def deobfuscate_file(
        self,
        input_path: str,
        session_path: str,
        session_password: str,
        output_path: Optional[str] = None,
    ) -> str:
        src    = Path(input_path).read_text(encoding="utf-8")
        result = self.deobfuscate_source(src, session_path, session_password)

        out = output_path or str(Path(input_path).with_suffix(".deobf.py"))
        Path(out).write_text(result, encoding="utf-8")
        return result

    # ── reversal pipeline ──────────────────────────────────────────────────────

    def _run_reversal(self, source: str, session: ObfuscationSession) -> str:
        # Strip header comment
        lines = source.splitlines()
        code_lines = [l for l in lines if not l.startswith("# Helioporbit")]
        source = "\n".join(code_lines)

        # Parse
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise ValueError(f"Cannot parse obfuscated source: {exc}") from exc

        # ── Phase 1: Restore strings (must happen before name de-mangling) ────
        tree = _StringRestorer().visit(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 2: Fold integers ────────────────────────────────────────────
        tree = _IntegerFolder().visit(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 3: Revert builtin aliases ───────────────────────────────────
        reverter = _BuiltinAliasReverter()
        tree = reverter.apply(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 4: Remove junk / bootstrap / dead code ──────────────────────
        tree = _JunkRemover().visit(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 5: Revert CFF ───────────────────────────────────────────────
        tree = _CFFReverter().visit(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 6: De-mangle names ──────────────────────────────────────────
        if session.reverse_name_map:
            tree = _NameDemangler(session.reverse_name_map).visit(tree)
            ast.fix_missing_locations(tree)

        # ── Phase 7: Clean empty bodies ───────────────────────────────────────
        tree = _EmptyBodyFixer().visit(tree)
        ast.fix_missing_locations(tree)

        # ── Phase 8: Unparse ──────────────────────────────────────────────────
        try:
            restored = ast.unparse(tree)
        except Exception as exc:
            raise RuntimeError(f"AST unparse failed during deobfuscation: {exc}") from exc

        header = (
            f"# Restored by Helioporbit Deobfuscator\n"
            f"# Original session: {session.session_id}\n"
            f"# Source hash (original): {session.source_hash}\n\n"
        )
        return header + restored


# ──────────────────────────────────────────────────────────────────────────────
# Utility: fix empty bodies left by dead-code removal
# ──────────────────────────────────────────────────────────────────────────────

class _EmptyBodyFixer(ast.NodeTransformer):
    def _fix(self, stmts: list) -> list:
        return stmts if stmts else [ast.Pass()]

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_If(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_For(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_While(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        return node

    def visit_Try(self, node):
        self.generic_visit(node)
        node.body = self._fix(node.body)
        for h in node.handlers:
            h.body = self._fix(h.body)
        return node

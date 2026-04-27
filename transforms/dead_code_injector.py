"""
helioporbit.transforms.dead_code_injector
Injects syntactically-valid but semantically-dead code at random points.

Dead code categories:
  A. Opaque predicates  — conditions always True/False via mathematical identities
  B. Unreachable blocks — code under "if False:" or never-triggered predicates
  C. Junk assignments   — assign to vars that are never read (unique mangled names)
  D. Fake function calls — calls to lambdas that return immediately
  E. Trivial loops      — "for _ in range(0):" blocks with real-looking body

Opaque predicate families (always-True):
  • n*(n+1) % 2 == 0  (product of consecutive ints is always even)
  • (x^2 + x) % 2 == 0
  • hash(id(object)) == hash(id(object))  ← same object
  • 7**2 + 11**2 != 3**4  (170 != 81)

Opaque predicate families (always-False):
  • n*(n+1) % 2 != 0
  • n*n < 0  (impossible for real ints)
"""

from __future__ import annotations

import ast
import random
import secrets
from typing import List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Opaque predicate AST builders
# ──────────────────────────────────────────────────────────────────────────────

def _op_always_true(rng: random.Random) -> ast.expr:
    choice = rng.randint(0, 4)
    if choice == 0:
        # n*(n+1) % 2 == 0
        n = rng.randint(1, 9999)
        return ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=n),
                    op=ast.Mult(),
                    right=ast.Constant(value=n + 1),
                ),
                op=ast.Mod(),
                right=ast.Constant(value=2),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)],
        )
    elif choice == 1:
        # a**2 >= 0
        a = rng.randint(2, 100)
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=a), op=ast.Pow(), right=ast.Constant(value=2)),
            ops=[ast.GtE()],
            comparators=[ast.Constant(value=0)],
        )
    elif choice == 2:
        # (a | b) >= (a & b)  always true for non-negative ints
        a = rng.randint(0, 255)
        b = rng.randint(0, 255)
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=a), op=ast.BitOr(), right=ast.Constant(value=b)),
            ops=[ast.GtE()],
            comparators=[ast.BinOp(left=ast.Constant(value=a), op=ast.BitAnd(), right=ast.Constant(value=b))],
        )
    elif choice == 3:
        # True
        return ast.Constant(value=True)
    else:
        # a + b == b + a
        a = rng.randint(1, 500)
        b = rng.randint(1, 500)
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=a), op=ast.Add(), right=ast.Constant(value=b)),
            ops=[ast.Eq()],
            comparators=[ast.BinOp(left=ast.Constant(value=b), op=ast.Add(), right=ast.Constant(value=a))],
        )


def _op_always_false(rng: random.Random) -> ast.expr:
    choice = rng.randint(0, 3)
    if choice == 0:
        # n*(n+1) % 2 != 0  (always false)
        n = rng.randint(1, 9999)
        return ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=n), op=ast.Mult(), right=ast.Constant(value=n+1)),
                op=ast.Mod(), right=ast.Constant(value=2)),
            ops=[ast.NotEq()], comparators=[ast.Constant(value=0)])
    elif choice == 1:
        # a**2 < 0  (impossible)
        a = rng.randint(2, 100)
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=a), op=ast.Pow(), right=ast.Constant(value=2)),
            ops=[ast.Lt()], comparators=[ast.Constant(value=0)])
    elif choice == 2:
        # False
        return ast.Constant(value=False)
    else:
        # a != a
        a = rng.randint(1, 9999)
        return ast.Compare(left=ast.Constant(value=a), ops=[ast.NotEq()], comparators=[ast.Constant(value=a)])


# ──────────────────────────────────────────────────────────────────────────────
# Dead statement factories
# ──────────────────────────────────────────────────────────────────────────────

def _junk_assign(rng: random.Random) -> ast.stmt:
    """Assign a random value to a unique junk variable."""
    var_name = "_jk" + secrets.token_hex(6)
    ops = [ast.Add(), ast.Sub(), ast.Mult(), ast.BitXor(), ast.BitAnd()]
    lhs = rng.randint(1, 0xFFFF)
    rhs = rng.randint(1, 0xFFFF)
    expr = ast.BinOp(
        left=ast.Constant(value=lhs),
        op=rng.choice(ops),
        right=ast.Constant(value=rhs),
    )
    node = ast.Assign(
        targets=[ast.Name(id=var_name, ctx=ast.Store())],
        value=expr,
        lineno=0, col_offset=0,
    )
    ast.fix_missing_locations(node)
    return node


def _dead_if_true(body_stmts: List[ast.stmt], rng: random.Random) -> ast.If:
    """if <opaque_true>: <body_stmts>  — code runs, looks like a branch."""
    node = ast.If(
        test=_op_always_true(rng),
        body=body_stmts or [ast.Pass()],
        orelse=[_junk_assign(rng)],
    )
    ast.fix_missing_locations(node)
    return node


def _dead_if_false(dead_stmts: List[ast.stmt], rng: random.Random) -> ast.If:
    """if <opaque_false>: <dead_stmts>  — code never runs."""
    node = ast.If(
        test=_op_always_false(rng),
        body=dead_stmts or [ast.Pass()],
        orelse=[],
    )
    ast.fix_missing_locations(node)
    return node


def _fake_for_loop(rng: random.Random) -> ast.For:
    """for _ in range(0): <junk>  — loop body never executes."""
    node = ast.For(
        target=ast.Name(id="_", ctx=ast.Store()),
        iter=ast.Call(
            func=ast.Name(id="range", ctx=ast.Load()),
            args=[ast.Constant(value=0)],
            keywords=[],
        ),
        body=[_junk_assign(rng) for _ in range(rng.randint(1, 3))],
        orelse=[],
    )
    ast.fix_missing_locations(node)
    return node


def _fake_assert(rng: random.Random) -> ast.Assert:
    """assert <always_true>, 'msg'  — passes at runtime, noise for reader."""
    node = ast.Assert(
        test=_op_always_true(rng),
        msg=ast.Constant(value=secrets.token_hex(4)),
    )
    ast.fix_missing_locations(node)
    return node


# ──────────────────────────────────────────────────────────────────────────────
# Main transformer
# ──────────────────────────────────────────────────────────────────────────────

class DeadCodeInjector(ast.NodeTransformer):
    """
    Walks each statement list and injects dead code at random intervals.
    ratio: fraction of original statements after which to insert junk (0–1).
    """

    def __init__(self, rng: Optional[random.Random] = None, ratio: float = 0.35):
        self.rng   = rng or random.Random()
        self.ratio = ratio

    def _inject_into_stmts(self, stmts: List[ast.stmt]) -> List[ast.stmt]:
        result: List[ast.stmt] = []
        for stmt in stmts:
            result.append(stmt)
            if self.rng.random() < self.ratio:
                result.append(self._random_dead_stmt(stmt))
        return result

    def _random_dead_stmt(self, context_stmt: ast.stmt) -> ast.stmt:
        choice = self.rng.randint(0, 4)
        if choice == 0:
            return _junk_assign(self.rng)
        elif choice == 1:
            return _dead_if_false([_junk_assign(self.rng)], self.rng)
        elif choice == 2:
            return _fake_for_loop(self.rng)
        elif choice == 3:
            return _fake_assert(self.rng)
        else:
            return _junk_assign(self.rng)

    def _transform_stmts(self, stmts: List[ast.stmt]) -> List[ast.stmt]:
        visited = [self.visit(s) for s in stmts]
        return self._inject_into_stmts(visited)

    def visit_Module(self, node: ast.Module) -> ast.Module:
        node.body = self._transform_stmts(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.body = self._transform_stmts(node.body)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.body = self._transform_stmts(node.body)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.body = self._transform_stmts(node.body)
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        node.body   = self._transform_stmts(node.body)
        node.orelse = self._transform_stmts(node.orelse) if node.orelse else []
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        node.body   = self._transform_stmts(node.body)
        node.orelse = self._transform_stmts(node.orelse) if node.orelse else []
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        node.body   = self._transform_stmts(node.body)
        node.orelse = self._transform_stmts(node.orelse) if node.orelse else []
        return node

    def visit_With(self, node: ast.With) -> ast.With:
        node.body = self._transform_stmts(node.body)
        return node

    def visit_Try(self, node: ast.Try) -> ast.Try:
        node.body    = self._transform_stmts(node.body)
        node.finalbody = self._transform_stmts(node.finalbody) if node.finalbody else []
        for handler in node.handlers:
            handler.body = self._transform_stmts(handler.body)
        return node

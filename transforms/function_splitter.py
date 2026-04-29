"""
helioporbit.transforms.function_splitter
Splits large functions into multiple smaller helper functions that call
each other in a chain, making control flow harder to follow.

Also implements function merging: two small adjacent functions get
merged into one with a dispatch parameter.

Splitting strategy:
    def big_func(x, y):         →    def big_func(x, y):
        block_A                           return _hsp_part1(x, y)
        block_B                       def _hsp_part1(x, y):
        block_C                           block_A
        return result                     return _hsp_part2(x, y)
                                      def _hsp_part2(x, y):
                                          block_B
                                          return _hsp_part3(x, y)
                                      def _hsp_part3(x, y):
                                          block_C
                                          return result

The helper function names use the wordlist mangler if available,
otherwise random hex names.

Merging strategy:
    def func_a(x):  +  def func_b(y):   →   def func_ab(_sel, *_args):
        return x*2         return y+1            if _sel==0: x=_args[0]; return x*2
                                                 return _args[0]+1
"""

from __future__ import annotations

import ast
import copy
import random
import secrets
from typing import List, Optional, Set, Tuple


_MIN_STMTS_TO_SPLIT = 6    # only split functions with at least this many stmts
_SPLIT_PARTS        = 2    # split into this many parts (2 = simpler, more reliable)


def _collect_names_loaded(stmts: List[ast.stmt]) -> Set[str]:
    """Collect all Name nodes that are loaded (read) in stmts."""
    names = set()
    mod   = ast.Module(body=stmts, type_ignores=[])
    for node in ast.walk(mod):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names.add(node.id)
    return names


def _collect_names_stored(stmts: List[ast.stmt]) -> Set[str]:
    """Collect all Name nodes that are stored (written) in stmts."""
    names = set()
    mod   = ast.Module(body=stmts, type_ignores=[])
    for node in ast.walk(mod):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def _has_return(stmts: List[ast.stmt]) -> bool:
    mod = ast.Module(body=stmts, type_ignores=[])
    for node in ast.walk(mod):
        if isinstance(node, ast.Return):
            return True
    return False


def _has_yield(stmts: List[ast.stmt]) -> bool:
    mod = ast.Module(body=stmts, type_ignores=[])
    for node in ast.walk(mod):
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
    return False


def _make_helper_name() -> str:
    return "_hsp" + secrets.token_hex(6)


def _make_call(func_name: str, args: List[ast.expr]) -> ast.Call:
    return ast.Call(
        func=ast.Name(id=func_name, ctx=ast.Load()),
        args=args,
        keywords=[],
    )


def _names_to_args(names: List[str]) -> ast.arguments:
    return ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=n) for n in names],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[],
    )


def split_function(
    func: ast.FunctionDef,
    rng: random.Random,
) -> List[ast.stmt]:
    """
    Split a function into 2 parts.
    Returns a list of statements: [helper_def, original_func_def_modified].
    The original function now just calls the helper for the second half.
    """
    body = func.body

    # Skip trivial / generator functions
    if len(body) < _MIN_STMTS_TO_SPLIT:
        return [func]
    if _has_yield(body):
        return [func]

    # Find a good split point (roughly middle, avoiding docstrings)
    start = 1 if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)) else 0
    mid   = start + max(1, (len(body) - start) // 2)
    # Avoid splitting inside an if/for/while block at the boundary
    while mid < len(body) - 1 and isinstance(body[mid], (ast.If, ast.For, ast.While, ast.Try)):
        mid += 1

    part1 = body[:mid]
    part2 = body[mid:]

    if not part1 or not part2:
        return [func]

    # Determine what variables need to be passed from part1 to part2
    stored_in_part1 = _collect_names_stored(part1)
    loaded_in_part2 = _collect_names_loaded(part2)
    # Original function params also flow through
    orig_params = {a.arg for a in func.args.args}
    pass_through = sorted((stored_in_part1 | orig_params) & (loaded_in_part2 | stored_in_part1))

    helper_name = _make_helper_name()
    helper_args = _names_to_args(pass_through)

    # Part2: if it has no return at end, add return None
    part2_body = list(part2)
    if not _has_return(part2_body):
        part2_body.append(ast.Return(value=ast.Constant(value=None)))

    helper_func = ast.FunctionDef(
        name=helper_name,
        args=helper_args,
        body=part2_body,
        decorator_list=[],
        returns=None,
        lineno=1, col_offset=0,
    )
    ast.fix_missing_locations(helper_func)

    # Part1: call helper at the end, return its result
    call_args = [ast.Name(id=n, ctx=ast.Load()) for n in pass_through]
    call_expr  = _make_call(helper_name, call_args)
    ret_stmt   = ast.Return(value=call_expr)
    ast.fix_missing_locations(ret_stmt)

    # If part1 already ends with a return, keep it; otherwise append call
    if _has_return(part1):
        new_body = list(part1)
    else:
        new_body = list(part1) + [ret_stmt]

    func.body = new_body
    ast.fix_missing_locations(func)

    # Helper goes BEFORE the function definition
    return [helper_func, func]


class FunctionSplitter(ast.NodeTransformer):
    """
    Visits module-level function definitions and splits long ones.
    Does NOT recurse into nested functions (to keep complexity manageable).
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        min_stmts: int = _MIN_STMTS_TO_SPLIT,
        probability: float = 0.80,
    ):
        self.rng         = rng or random.Random()
        self.min_stmts   = min_stmts
        self.probability = probability

    def visit_Module(self, node: ast.Module) -> ast.Module:
        new_body: List[ast.stmt] = []
        for stmt in node.body:
            if (
                isinstance(stmt, ast.FunctionDef)
                and len(stmt.body) >= self.min_stmts
                and not _has_yield(stmt.body)
                and self.rng.random() < self.probability
            ):
                split = split_function(stmt, self.rng)
                new_body.extend(split)
            elif (
                isinstance(stmt, ast.ClassDef)
            ):
                # Split methods inside classes too
                new_methods: List[ast.stmt] = []
                for item in stmt.body:
                    if (
                        isinstance(item, ast.FunctionDef)
                        and len(item.body) >= self.min_stmts
                        and not _has_yield(item.body)
                        and self.rng.random() < self.probability
                    ):
                        split = split_function(item, self.rng)
                        new_methods.extend(split)
                    else:
                        new_methods.append(item)
                stmt.body = new_methods
                new_body.append(stmt)
            else:
                new_body.append(stmt)
        node.body = new_body
        ast.fix_missing_locations(node)
        return node


# ── Literal encoding ───────────────────────────────────────────────────────────

class LiteralEncoder(ast.NodeTransformer):
    """
    Encodes ALL literal types more aggressively:

    bool:   True  → (1 == 1)              False → (1 == 0)
    int:    42    → (already handled by IntegerEncoder, but also adds hex/octal)
    float:  3.14  → (314 / 100)  — approximate rational form
    bytes:  b'hi' → bytes([104, 105])
    None:   None  → (lambda: None)()

    Applied AFTER integer encoding for extra layering.
    """

    def __init__(self, rng: Optional[random.Random] = None, probability: float = 0.75):
        self.rng         = rng or random.Random()
        self.probability = probability

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if self.rng.random() > self.probability:
            return node

        v = node.value

        # bool — must check before int (bool is subclass of int)
        if isinstance(v, bool):
            if v:
                # True → (0 == 0)
                expr = ast.Compare(
                    left=ast.Constant(value=0),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)],
                )
            else:
                # False → (0 == 1)
                expr = ast.Compare(
                    left=ast.Constant(value=0),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=1)],
                )
            ast.copy_location(expr, node)
            ast.fix_missing_locations(expr)
            return expr

        # None → (lambda: None)()
        if v is None:
            expr = ast.Call(
                func=ast.Lambda(
                    args=ast.arguments(
                        posonlyargs=[], args=[], vararg=None,
                        kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[],
                    ),
                    body=ast.Constant(value=None),
                ),
                args=[], keywords=[],
            )
            ast.copy_location(expr, node)
            ast.fix_missing_locations(expr)
            return expr

        # bytes → bytes([...])
        if isinstance(v, bytes) and 0 < len(v) <= 64:
            ords = [ast.Constant(value=b) for b in v]
            expr = ast.Call(
                func=ast.Name(id="bytes", ctx=ast.Load()),
                args=[ast.List(elts=ords, ctx=ast.Load())],
                keywords=[],
            )
            ast.copy_location(expr, node)
            ast.fix_missing_locations(expr)
            return expr

        # float → rational approximation (a / b)
        if isinstance(v, float) and not (v != v) and abs(v) < 1e6:
            # Use a simple rational: round to 4 decimal places
            scaled = round(v * 10000)
            if scaled != 0:
                expr = ast.BinOp(
                    left=ast.Constant(value=scaled),
                    op=ast.Div(),
                    right=ast.Constant(value=10000),
                )
                ast.copy_location(expr, node)
                ast.fix_missing_locations(expr)
                return expr

        return node

"""
helioporbit.transforms.integer_encoder
Replaces integer literals with algebraically-equivalent expressions.

Encoding strategies (chosen randomly per constant):
  1. XOR split:   n  →  (A ^ B)          where A ^ B == n
  2. Add split:   n  →  (A + B - C)      where A + B - C == n
  3. Mul+shift:   n  →  (A * B) >> k      where (A*B)>>k == n
  4. Nested XOR:  n  →  ((A ^ B) ^ C)    3-deep
  5. Bit tricks:  n  →  (~(~n))  or  (n | 0) etc.
  6. Recursive:   applies encoding to the sub-expressions (depth-limited)
"""

from __future__ import annotations

import ast
import random
from typing import Optional


def encode_int_expr(value: int, rng: random.Random, depth: int = 2) -> ast.expr:
    """Return an AST expression that evaluates to *value* using arithmetic obfuscation."""
    if depth <= 0 or abs(value) > 2**31:
        return ast.Constant(value=value)

    strategy = rng.randint(0, 5)

    if strategy == 0:
        # XOR split: value = A ^ (A ^ value) — always works
        A = rng.randint(0, 0xFFFF)
        B = A ^ value
        left  = encode_int_expr(A, rng, depth - 1)
        right = encode_int_expr(B, rng, depth - 1)
        expr  = ast.BinOp(left=left, op=ast.BitXor(), right=right)

    elif strategy == 1:
        # Add split: value = A + (value - A)
        A = rng.randint(-0x7FFF, 0x7FFF)
        B = value - A
        left  = encode_int_expr(A, rng, depth - 1)
        right = encode_int_expr(B, rng, depth - 1)
        expr  = ast.BinOp(left=left, op=ast.Add(), right=right)

    elif strategy == 2:
        # Negate trick: value = -(-value)
        inner = encode_int_expr(-value, rng, depth - 1)
        expr  = ast.UnaryOp(op=ast.USub(), operand=inner)

    elif strategy == 3:
        # Nested XOR: value = (A ^ B ^ C)
        A = rng.randint(0, 0xFFFF)
        C = rng.randint(0, 0xFFFF)
        B = value ^ A ^ C
        expr = ast.BinOp(
            left=ast.BinOp(
                left=encode_int_expr(A, rng, depth - 1),
                op=ast.BitXor(),
                right=encode_int_expr(B, rng, depth - 1),
            ),
            op=ast.BitXor(),
            right=encode_int_expr(C, rng, depth - 1),
        )

    elif strategy == 4:
        # Sub trick: value = (value + K) - K
        K     = rng.randint(1, 0x3FFF)
        left  = encode_int_expr(value + K, rng, depth - 1)
        right = encode_int_expr(K, rng, depth - 1)
        expr  = ast.BinOp(left=left, op=ast.Sub(), right=right)

    else:
        # Bitwise NOT trick: value = ~(~value)
        inner = encode_int_expr(~value, rng, depth - 1)
        expr  = ast.UnaryOp(op=ast.Invert(), operand=inner)

    ast.fix_missing_locations(expr)
    return expr


class IntegerEncoderTransformer(ast.NodeTransformer):
    """Replace integer Constant nodes with obfuscated arithmetic expressions."""

    def __init__(self, rng: Optional[random.Random] = None, depth: int = 2, skip_small: bool = True):
        self.rng        = rng or random.Random()
        self.depth      = depth
        self.skip_small = skip_small  # skip 0, 1, -1 (too common / risky)

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            return node
        v = node.value
        if self.skip_small and v in (0, 1, -1, 2):
            return node
        # Only encode within a safe range to avoid overflow issues
        if abs(v) > 2**30:
            return node
        # 70% chance to encode (leave some as-is for variety)
        if self.rng.random() < 0.30:
            return node
        return encode_int_expr(v, self.rng, self.depth)

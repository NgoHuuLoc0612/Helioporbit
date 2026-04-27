"""
helioporbit.transforms.string_splitter
Splits string literals into multiple concatenated fragments using a mix of:
  - Raw hex escape sequences  (\x48\x65\x6c\x6c\x6f)
  - Unicode escapes           (\u0048\u0065\u006c\u006c\u006f)
  - Reversed + reversed       'olleh'[::-1]
  - Base64 decode inline      __import__('base64').b64decode(b'...').decode()
  - Chr() join                ''.join(map(chr,[72,101,108,108,111]))
  - Mixed splitting           'He' + '\x6c\x6c' + '\u006f'

Applied BEFORE encryption — so even the plaintext form (if someone strips
the encryption layer) still shows unreadable fragments instead of clear strings.

This is a source-level transform only — no runtime overhead beyond
what Python's string constant folding already handles for static cases.
"""

from __future__ import annotations

import ast
import base64
import random
import textwrap
from typing import Optional


# Minimum string length to bother splitting
_MIN_SPLIT_LEN = 4
# Maximum string length to use chr() join (too long = ugly code)
_MAX_CHR_LEN   = 40


def _hex_escape(s: str) -> str:
    """Encode every character as \\xNN."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def _unicode_escape(s: str) -> str:
    """Encode every character as \\uNNNN."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _chr_join_node(s: str) -> ast.expr:
    """''.join(map(chr, [72, 101, 108, ...])) as AST node."""
    ords = [ast.Constant(value=ord(c)) for c in s]
    return ast.Call(
        func=ast.Attribute(
            value=ast.Constant(value=""),
            attr="join",
            ctx=ast.Load(),
        ),
        args=[
            ast.Call(
                func=ast.Name(id="map", ctx=ast.Load()),
                args=[
                    ast.Name(id="chr", ctx=ast.Load()),
                    ast.List(elts=ords, ctx=ast.Load()),
                ],
                keywords=[],
            )
        ],
        keywords=[],
    )


def _reverse_node(s: str) -> ast.expr:
    """'<reversed_string>'[::-1] as AST node."""
    rev = s[::-1]
    return ast.Subscript(
        value=ast.Constant(value=rev),
        slice=ast.Slice(
            lower=None,
            upper=None,
            step=ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1)),
        ),
        ctx=ast.Load(),
    )


def _b64_decode_node(s: str) -> ast.expr:
    """__import__('base64').b64decode(b'...').decode() as AST node."""
    b64 = base64.b64encode(s.encode()).decode()
    return ast.Call(
        func=ast.Attribute(
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Name(id="__import__", ctx=ast.Load()),
                        args=[ast.Constant(value="base64")],
                        keywords=[],
                    ),
                    attr="b64decode",
                    ctx=ast.Load(),
                ),
                args=[ast.Constant(value=b64.encode())],
                keywords=[],
            ),
            attr="decode",
            ctx=ast.Load(),
        ),
        args=[],
        keywords=[],
    )


def _hex_str_node(s: str) -> ast.expr:
    """A string constant encoded entirely as hex escapes."""
    return ast.Constant(value=bytes.fromhex(
        "".join(f"{ord(c):02x}" for c in s)
    ).decode("latin-1"))


def _split_concat_node(s: str, rng: random.Random) -> ast.expr:
    """Split string into 2-4 fragments joined by BinOp(Add)."""
    n      = rng.randint(2, min(4, max(2, len(s) // 3)))
    size   = max(1, len(s) // n)
    chunks = [s[i:i + size] for i in range(0, len(s), size)]
    # Last chunk absorbs remainder
    if len(chunks) > n:
        chunks[-2] = chunks[-2] + chunks[-1]
        chunks = chunks[:-1]

    nodes = []
    for chunk in chunks:
        style = rng.randint(0, 2)
        if style == 0:
            nodes.append(ast.Constant(value=chunk))
        elif style == 1:
            # hex escape literal
            nodes.append(ast.Constant(value=bytes(
                [ord(c) for c in chunk]
            ).decode("latin-1")))
        else:
            # Just the plain chunk (variety)
            nodes.append(ast.Constant(value=chunk))

    # Build left-associative BinOp(Add) chain
    result = nodes[0]
    for node in nodes[1:]:
        result = ast.BinOp(left=result, op=ast.Add(), right=node)
    return result


class StringSplitterTransformer(ast.NodeTransformer):
    """
    Replaces string Constant nodes with obfuscated expression equivalents.
    Each string gets a randomly chosen obfuscation method.
    Works on the RAW source BEFORE encryption — adds an extra layer so that
    even if someone strips the encryption bootstrap, strings are still mangled.

    Methods (chosen randomly per string):
      0 = split + concatenate fragments
      1 = chr() join via map()
      2 = reverse slice [::-1]
      3 = base64 decode inline
      4 = plain (no change, for variety / short strings)
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        probability: float = 0.7,
        min_length: int = _MIN_SPLIT_LEN,
    ):
        self.rng         = rng or random.Random()
        self.probability = probability
        self.min_length  = min_length
        self._in_import  = False

    def visit_Import(self, node):
        return node

    def visit_ImportFrom(self, node):
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if not isinstance(node.value, str):
            return node
        s = node.value
        if len(s) < self.min_length:
            return node
        if self.rng.random() > self.probability:
            return node

        method = self.rng.randint(0, 4)

        try:
            if method == 0:
                new_node = _split_concat_node(s, self.rng)
            elif method == 1 and len(s) <= _MAX_CHR_LEN:
                new_node = _chr_join_node(s)
            elif method == 2:
                new_node = _reverse_node(s)
            elif method == 3 and len(s) <= _MAX_CHR_LEN:
                new_node = _b64_decode_node(s)
            else:
                new_node = _split_concat_node(s, self.rng)

            ast.copy_location(new_node, node)
            ast.fix_missing_locations(new_node)
            return new_node
        except Exception:
            return node

    def visit_JoinedStr(self, node):
        # Skip f-strings entirely
        return node

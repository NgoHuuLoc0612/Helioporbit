"""
helioporbit.transforms.junk_class_injector
Injects realistic-looking but completely useless class/function definitions.
These look like real business logic to a reader but do nothing meaningful.

Also includes CommentPolluter which adds misleading comment blocks.
"""

from __future__ import annotations

import ast
import random
import secrets
import textwrap
from typing import List, Optional


# ── Junk class templates ───────────────────────────────────────────────────────

def _make_junk_class(name: str, rng: random.Random) -> ast.ClassDef:
    """
    Generates a class that looks like real infrastructure code but is never used.
    Example output:
        class _RequestContextManager:
            _instance = None
            _timeout  = 30
            def __init__(self): self._data = {}
            def acquire(self, key): return self._data.get(key)
            def release(self, key): self._data.pop(key, None)
    """
    timeout_val = rng.randint(10, 120)
    limit_val   = rng.randint(100, 10000)
    key_val     = secrets.token_hex(8)

    # Build class body
    body: List[ast.stmt] = []

    # Class-level attributes
    body.append(ast.Assign(
        targets=[ast.Name(id="_instance", ctx=ast.Store())],
        value=ast.Constant(value=None),
        lineno=1, col_offset=0,
    ))
    body.append(ast.Assign(
        targets=[ast.Name(id="_timeout", ctx=ast.Store())],
        value=ast.Constant(value=timeout_val),
        lineno=1, col_offset=0,
    ))
    body.append(ast.Assign(
        targets=[ast.Name(id="_limit", ctx=ast.Store())],
        value=ast.Constant(value=limit_val),
        lineno=1, col_offset=0,
    ))

    # __init__
    init_body = [
        ast.Assign(
            targets=[ast.Attribute(
                value=ast.Name(id="self", ctx=ast.Load()),
                attr="_data", ctx=ast.Store()
            )],
            value=ast.Dict(keys=[], values=[]),
            lineno=1, col_offset=0,
        ),
        ast.Assign(
            targets=[ast.Attribute(
                value=ast.Name(id="self", ctx=ast.Load()),
                attr="_ready", ctx=ast.Store()
            )],
            value=ast.Constant(value=False),
            lineno=1, col_offset=0,
        ),
    ]
    body.append(ast.FunctionDef(
        name="__init__",
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg="self")],
            vararg=None, kwonlyargs=[], kw_defaults=[],
            kwarg=None, defaults=[],
        ),
        body=init_body, decorator_list=[], returns=None,
        lineno=1, col_offset=0,
    ))

    # acquire method
    body.append(ast.FunctionDef(
        name="acquire",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="self"), ast.arg(arg="key")],
            vararg=None, kwonlyargs=[], kw_defaults=[],
            kwarg=None, defaults=[],
        ),
        body=[ast.Return(value=ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="self", ctx=ast.Load()),
                    attr="_data", ctx=ast.Load()
                ),
                attr="get", ctx=ast.Load()
            ),
            args=[ast.Name(id="key", ctx=ast.Load())],
            keywords=[],
        ))],
        decorator_list=[], returns=None,
        lineno=1, col_offset=0,
    ))

    # release method
    body.append(ast.FunctionDef(
        name="release",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="self"), ast.arg(arg="key")],
            vararg=None, kwonlyargs=[], kw_defaults=[],
            kwarg=None, defaults=[],
        ),
        body=[ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="self", ctx=ast.Load()),
                    attr="_data", ctx=ast.Load()
                ),
                attr="pop", ctx=ast.Load()
            ),
            args=[ast.Name(id="key", ctx=ast.Load()), ast.Constant(value=None)],
            keywords=[],
        ))],
        decorator_list=[], returns=None,
        lineno=1, col_offset=0,
    ))

    cls = ast.ClassDef(
        name=name,
        bases=[],
        keywords=[],
        body=body,
        decorator_list=[],
        lineno=1, col_offset=0,
    )
    ast.fix_missing_locations(cls)
    return cls


def _make_junk_function(name: str, rng: random.Random) -> ast.FunctionDef:
    """
    Generates a function that looks like a utility but does nothing useful.
    """
    param_names = rng.sample(["data", "key", "value", "config", "ctx", "opts", "payload", "token"], 2)
    magic = rng.randint(1000, 9999)

    body = [
        ast.If(
            test=ast.Compare(
                left=ast.Name(id=param_names[0], ctx=ast.Load()),
                ops=[ast.Is()],
                comparators=[ast.Constant(value=None)],
            ),
            body=[ast.Return(value=ast.Constant(value=None))],
            orelse=[],
        ),
        ast.Assign(
            targets=[ast.Name(id="_result", ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.Call(
                    func=ast.Name(id="hash", ctx=ast.Load()),
                    args=[ast.Name(id=param_names[0], ctx=ast.Load())],
                    keywords=[],
                ),
                op=ast.BitAnd(),
                right=ast.Constant(value=magic),
            ),
            lineno=1, col_offset=0,
        ),
        ast.Return(value=ast.Name(id="_result", ctx=ast.Load())),
    ]

    fn = ast.FunctionDef(
        name=name,
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=p) for p in param_names],
            vararg=None, kwonlyargs=[], kw_defaults=[],
            kwarg=None, defaults=[ast.Constant(value=None)],
        ),
        body=body,
        decorator_list=[],
        returns=None,
        lineno=1, col_offset=0,
    )
    ast.fix_missing_locations(fn)
    return fn


# ── Comment polluter (source-level post-process) ───────────────────────────────

_COMMENT_TEMPLATES = [
    "# TODO: refactor this after v{v} release",
    "# FIXME: edge case when {w} is None",
    "# NOTE: do not change the order of operations here",
    "# legacy compatibility layer -- see issue #{n}",
    "# optimized path for {w} > {n} items",
    "# WARNING: not thread-safe, caller must hold the lock",
    "# type: ignore[assignment]",
    "# noqa: E501",
    "# pragma: no cover",
    "# fmt: off",
    "# pylint: disable={w}",
    "# {w} = {v}.{n}",
    "# deprecated since {v}.{n}, use {w}() instead",
    "# perf: avoid dict lookup on hot path",
    "# security: do not log this value",
    "# internal use only",
    "# fallback for Python < 3.{n}",
    "# see RFC {n} section {v}.{n}",
]

_COMMENT_WORDS = [
    "handler", "parser", "manager", "context", "registry", "dispatcher",
    "validator", "serializer", "transform", "middleware", "resolver",
    "cache_miss", "session_id", "token", "payload", "checksum", "offset",
    "cursor", "buffer", "chunk", "frame", "packet", "retry_count",
]


def _random_comment(rng: random.Random) -> str:
    tmpl = rng.choice(_COMMENT_TEMPLATES)
    return tmpl.format(
        v=f"{rng.randint(1,4)}.{rng.randint(0,9)}",
        n=rng.randint(10, 9999),
        w=rng.choice(_COMMENT_WORDS),
    )


def pollute_with_comments(source: str, rng: random.Random, density: float = 0.25) -> str:
    """
    Insert misleading comment lines into the source text.
    density: probability of inserting a comment after each non-blank line.
    """
    lines  = source.splitlines()
    result = []
    for line in lines:
        result.append(line)
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("#")
            and not stripped.startswith('"""')
            and not stripped.startswith("'''")
            and rng.random() < density
        ):
            indent = len(line) - len(line.lstrip())
            comment = " " * indent + _random_comment(rng)
            result.append(comment)
    return "\n".join(result)


# ── Main injector transformer ──────────────────────────────────────────────────

class JunkClassInjector(ast.NodeTransformer):
    """
    Injects fake class and function definitions at random positions
    in the module body. They look real but are never called.
    """

    def __init__(
        self,
        class_names: List[str],
        func_names:  List[str],
        rng: Optional[random.Random] = None,
    ):
        self.class_names = class_names
        self.func_names  = func_names
        self.rng         = rng or random.Random()

    def visit_Module(self, node: ast.Module) -> ast.Module:
        self.generic_visit(node)

        extras: List[ast.stmt] = []

        for name in self.class_names:
            extras.append(_make_junk_class(name, self.rng))

        for name in self.func_names:
            extras.append(_make_junk_function(name, self.rng))

        # Scatter extras at random positions within non-import stmts
        body   = list(node.body)
        # Find insertion range (after imports)
        start  = 0
        for i, s in enumerate(body):
            if isinstance(s, (ast.Import, ast.ImportFrom)):
                start = i + 1

        positions = sorted(
            self.rng.sample(range(start, len(body) + 1), min(len(extras), max(1, len(body) - start))),
            reverse=True,
        )
        for pos, extra in zip(positions, extras):
            body.insert(pos, extra)

        node.body = body
        return node

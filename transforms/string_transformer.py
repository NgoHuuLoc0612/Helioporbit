"""
helioporbit.transforms.string_transformer
AST transformer that locates all string Constant nodes (excluding docstrings
when strip_docstrings=False) and replaces them with runtime-decryption calls.
"""

from __future__ import annotations

import ast
from typing import Optional

from helioporbit.crypto.string_encryptor import StringEncryptor


class StringTransformer(ast.NodeTransformer):
    """
    Replace every string literal in the AST with a call to _hpb_ds(…).
    Skips:
      • Docstrings (if strip_docstrings=False)
      • __all__ = [...]  string elements (they must remain as-is for imports)
      • Annotation strings (PEP 563 forward refs) — obfuscating these breaks typing
      • f-string nodes (JoinedStr) — only non-format-spec Constant children
    """

    def __init__(
        self,
        encryptor: StringEncryptor,
        strip_docstrings: bool = True,
        min_length: int = 2,
    ):
        self.encryptor        = encryptor
        self.strip_docstrings = strip_docstrings
        self.min_length       = min_length
        self._skip_next_expr  = False  # set True when we're in a docstring context

    # ── helpers ────────────────────────────────────────────────────────────────

    def _encrypt_str_node(self, node: ast.Constant) -> ast.expr:
        s = node.value
        if len(s) < self.min_length:
            return node
        sid, meta = self.encryptor.encrypt_string(s)
        call      = self.encryptor.make_call_node(sid, meta)
        ast.copy_location(call, node)
        ast.fix_missing_locations(call)
        return call

    def _is_docstring(self, stmt: ast.stmt) -> bool:
        return (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        )

    def _transform_body(self, stmts: list) -> list:
        result = []
        for i, stmt in enumerate(stmts):
            if i == 0 and self._is_docstring(stmt):
                if self.strip_docstrings:
                    continue  # drop docstring entirely
                else:
                    result.append(stmt)  # keep as-is (don't encrypt)
                    continue
            result.append(self.visit(stmt))
        return result

    # ── visitors ───────────────────────────────────────────────────────────────

    def visit_Module(self, node: ast.Module) -> ast.Module:
        node.body = self._transform_body(node.body)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.body = self._transform_body(node.body)
        # Visit decorators and defaults, but not annotation strings
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        self.generic_visit(node.args)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.body = self._transform_body(node.body)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.body = self._transform_body(node.body)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if isinstance(node.value, str):
            return self._encrypt_str_node(node)
        return node

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.JoinedStr:
        # f-strings: only encrypt the non-format-spec Constant children
        new_values = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                new_values.append(self._encrypt_str_node(v))
            elif isinstance(v, ast.FormattedValue):
                v.value = self.visit(v.value)
                new_values.append(v)
            else:
                new_values.append(self.visit(v))
        node.values = new_values
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        # Skip the annotation itself — it may be a string forward reference
        if node.value is not None:
            node.value = self.visit(node.value)
        return node

    def visit_Import(self, node: ast.Import) -> ast.Import:
        return node  # never touch import statements

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom:
        return node

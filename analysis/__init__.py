"""
helioporbit.analysis
Post-obfuscation quality analysis tools.

Metrics computed:
  • Shannon entropy of the output source
  • AST node count before/after
  • Name collision rate
  • Cyclomatic complexity (McCabe) before/after
  • String encryption coverage
  • Control-flow flattening coverage
  • Estimated deobfuscation resistance score (0–100)
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ──────────────────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per character) of *data*."""
    if not data:
        return 0.0
    freq = Counter(data)
    n    = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ──────────────────────────────────────────────────────────────────────────────
# AST metrics
# ──────────────────────────────────────────────────────────────────────────────

def ast_node_count(source: str) -> int:
    try:
        tree = ast.parse(source)
        return sum(1 for _ in ast.walk(tree))
    except SyntaxError:
        return -1


def cyclomatic_complexity(source: str) -> int:
    """
    Approximate McCabe cyclomatic complexity for the entire module.
    CC = number of decision points + 1.
    Decision points: if, elif, for, while, except, and, or, with, assert.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return -1

    decision_nodes = (
        ast.If, ast.For, ast.While, ast.ExceptHandler,
        ast.Assert, ast.With, ast.AsyncFor, ast.AsyncWith,
    )
    count = 1
    for node in ast.walk(tree):
        if isinstance(node, decision_nodes):
            count += 1
        elif isinstance(node, ast.BoolOp):
            # Each 'and'/'or' adds a branch
            count += len(node.values) - 1
    return count


def _count_string_literals(tree: ast.Module) -> int:
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _count_hpb_ds_calls(tree: ast.Module) -> int:
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_hpb_ds"
    )


def _count_cff_while(tree: ast.Module) -> int:
    """Count while-True loops that are part of CFF (contain _hpb_st comparisons)."""
    count = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and node.test.value is True
        ):
            src = ast.unparse(node)
            if "_hpb_st" in src:
                count += 1
    return count


# ──────────────────────────────────────────────────────────────────────────────
# Resistance score
# ──────────────────────────────────────────────────────────────────────────────

def resistance_score(metrics: "AnalysisReport") -> int:
    """
    Composite score 0–100 estimating resistance to automated deobfuscation.
    Higher is better (harder to reverse without session key).
    """
    score = 0

    # Entropy (max 6.0 bits/char is ideal for obfuscated code)
    e = metrics.obf_entropy
    score += min(25, int((e / 6.0) * 25))

    # String encryption coverage (% of strings encrypted)
    cov = metrics.string_encryption_coverage
    score += int(cov * 20)

    # CFF coverage
    cff = metrics.cff_function_coverage
    score += int(cff * 20)

    # Name mangling: identifier diversity (% unique identifiers)
    if metrics.total_identifiers > 0:
        div = metrics.unique_identifiers / metrics.total_identifiers
        score += int(div * 15)

    # Dead code ratio (injected stmts / total)
    dc = min(1.0, metrics.dead_code_ratio)
    score += int(dc * 10)

    # AST size inflation (obf / orig)
    if metrics.orig_ast_nodes > 0:
        inflation = metrics.obf_ast_nodes / metrics.orig_ast_nodes
        score += min(10, int((inflation - 1) * 5))

    return min(100, score)


# ──────────────────────────────────────────────────────────────────────────────
# Report dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisReport:
    # Source sizes
    orig_source_len: int           = 0
    obf_source_len: int            = 0

    # Entropy
    orig_entropy: float            = 0.0
    obf_entropy: float             = 0.0

    # AST
    orig_ast_nodes: int            = 0
    obf_ast_nodes: int             = 0

    # Cyclomatic complexity
    orig_complexity: int           = 0
    obf_complexity: int            = 0

    # String encryption
    orig_string_count: int         = 0
    obf_string_count: int          = 0     # remaining plaintext strings
    encrypted_strings: int         = 0
    string_encryption_coverage: float = 0.0

    # CFF
    cff_functions_flattened: int   = 0
    total_functions: int           = 0
    cff_function_coverage: float   = 0.0

    # Names
    total_identifiers: int         = 0
    unique_identifiers: int        = 0
    mangled_names: int             = 0

    # Dead code
    injected_dead_stmts: int       = 0
    total_obf_stmts: int           = 0
    dead_code_ratio: float         = 0.0

    # Score
    resistance_score: int          = 0

    def summary(self) -> str:
        lines = [
            "═" * 60,
            "  HELIOPORBIT — Obfuscation Analysis Report",
            "═" * 60,
            f"  Source size          : {self.orig_source_len:>8,} → {self.obf_source_len:>8,} bytes",
            f"  Size inflation       : {self.obf_source_len / max(1, self.orig_source_len):.2f}×",
            f"  Shannon entropy      : {self.orig_entropy:.3f} → {self.obf_entropy:.3f} bits/char",
            f"  AST nodes            : {self.orig_ast_nodes:>8,} → {self.obf_ast_nodes:>8,}",
            f"  Cyclomatic complexity: {self.orig_complexity:>8,} → {self.obf_complexity:>8,}",
            "─" * 60,
            f"  Strings encrypted    : {self.encrypted_strings} / {self.orig_string_count}  "
            f"({self.string_encryption_coverage*100:.1f}%)",
            f"  Functions CFF'd      : {self.cff_functions_flattened} / {self.total_functions}  "
            f"({self.cff_function_coverage*100:.1f}%)",
            f"  Names mangled        : {self.mangled_names}",
            f"  Dead stmts injected  : {self.injected_dead_stmts} / {self.total_obf_stmts}  "
            f"({self.dead_code_ratio*100:.1f}%)",
            "─" * 60,
            f"  ★ Resistance score   : {self.resistance_score} / 100",
            "═" * 60,
        ]
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Analyser
# ──────────────────────────────────────────────────────────────────────────────

class Analyser:
    """Compute before/after metrics for an obfuscation run."""

    def analyse(
        self,
        original_source: str,
        obfuscated_source: str,
        name_map: Optional[Dict[str, str]] = None,
        cff_map: Optional[Dict[str, list]] = None,
    ) -> AnalysisReport:
        r = AnalysisReport()

        # Sizes & entropy
        r.orig_source_len = len(original_source.encode())
        r.obf_source_len  = len(obfuscated_source.encode())
        r.orig_entropy    = shannon_entropy(original_source)
        r.obf_entropy     = shannon_entropy(obfuscated_source)

        # AST & complexity
        r.orig_ast_nodes  = ast_node_count(original_source)
        r.obf_ast_nodes   = ast_node_count(obfuscated_source)
        r.orig_complexity = cyclomatic_complexity(original_source)
        r.obf_complexity  = cyclomatic_complexity(obfuscated_source)

        # String coverage
        try:
            orig_tree = ast.parse(original_source)
            obf_tree  = ast.parse(obfuscated_source)
            r.orig_string_count      = _count_string_literals(orig_tree)
            r.obf_string_count       = _count_string_literals(obf_tree)
            r.encrypted_strings      = _count_hpb_ds_calls(obf_tree)
            total_strings = r.orig_string_count or 1
            r.string_encryption_coverage = min(1.0, r.encrypted_strings / total_strings)

            # CFF
            r.cff_functions_flattened = _count_cff_while(obf_tree)
            r.total_functions = sum(
                1 for n in ast.walk(orig_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            if r.total_functions:
                r.cff_function_coverage = min(1.0, r.cff_functions_flattened / r.total_functions)

            # Identifiers
            all_ids = [
                n.id for n in ast.walk(obf_tree)
                if isinstance(n, ast.Name)
            ]
            r.total_identifiers  = len(all_ids)
            r.unique_identifiers = len(set(all_ids))

            # Dead code: count _jk* assignments
            r.injected_dead_stmts = sum(
                1 for n in ast.walk(obf_tree)
                if isinstance(n, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id.startswith("_jk")
                    for t in n.targets
                )
            )
            r.total_obf_stmts = sum(
                1 for n in ast.walk(obf_tree)
                if isinstance(n, ast.stmt)
            )
            if r.total_obf_stmts:
                r.dead_code_ratio = r.injected_dead_stmts / r.total_obf_stmts

        except (SyntaxError, Exception):
            pass

        # Name mangling
        r.mangled_names = len(name_map) if name_map else 0

        # CFF from session
        if cff_map:
            r.cff_functions_flattened = max(r.cff_functions_flattened, len(cff_map))

        # Score
        r.resistance_score = resistance_score(r)
        return r

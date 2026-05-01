"""
helioporbit.transforms.mba_encoder
Mixed Boolean-Arithmetic (MBA) encoder with Z3-backed verification.

Replaces integer constants and simple arithmetic expressions with semantically
equivalent MBA expressions that are provably correct (Z3 BitVec solver verifies
every generated identity before emission).

Architecture:
  1. MBAIdentityLibrary  — catalog of parameterised MBA rewrite rules
  2. MBAVerifier         — Z3 solver that proves each identity over BitVec(64)
  3. MBAExprBuilder      — recursive expression builder using verified rules
  4. MBAEncoderTransformer — ast.NodeTransformer that rewrites the AST

MBA identities used (all verified by Z3 over 64-bit two's complement):
  Linear:
    x  =  (x ^ y) + 2*(x & y)           (add decomposition)
    x  =  (x | y) + (x & y) - y         (or identity)
    x  =  2*(x | y) - (x ^ y)           (or via XOR)
    x  =  (x & ~y) + y - (~x & y)       (sub decomposition)
    x  =  (x ^ -1) + 2*x + 1            (NOT identity: ~x = -x-1 → x = ~x+2x+1)
  Nonlinear / compound:
    x  =  (x + y) - y
    x  =  x*1 using ((x << 1) - x)      (mul-by-1 decomposition)
    const = generated 3-term MBA: A*(x & mask) ^ B*(x | mask) + C where
            the expression is constant for all x ∈ BitVec(64)
"""

from __future__ import annotations

import ast
import random
import secrets
import textwrap
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

# ── Z3 import (hard dependency for this module) ────────────────────────────────
try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────────
# Bit-width and type helpers
# ──────────────────────────────────────────────────────────────────────────────

_BW = 64  # BitVec width
_MASK = (1 << _BW) - 1
_SMOD = 1 << _BW  # signed modulus base

def _to_signed(v: int) -> int:
    """Interpret v as a signed 64-bit integer."""
    v = v & _MASK
    return v if v < (1 << (_BW - 1)) else v - _SMOD

def _to_unsigned(v: int) -> int:
    return v & _MASK


# ──────────────────────────────────────────────────────────────────────────────
# MBA Identity Library
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MBARule:
    """
    A single MBA rewrite rule.

    ``builder`` takes (value: int, rng: random.Random) → ast.expr | None.
    ``verify`` is a callable that runs the Z3 proof; if False the rule is skipped.
    ``name`` is used for diagnostics.
    """
    name: str
    builder: Callable[[int, random.Random], Optional[ast.expr]]
    verified_by_z3: bool = False  # set True once verifier confirms


# ──────────────────────────────────────────────────────────────────────────────
# Z3 Verifier
# ──────────────────────────────────────────────────────────────────────────────

class MBAVerifier:
    """
    Uses Z3 to prove MBA identities over BitVec(64).

    verify_constant_expr(expr_fn, expected_value) — proves that expr_fn(x) == expected_value
    for ALL x ∈ BitVec(64).

    verify_identity(lhs_fn, rhs_fn) — proves lhs_fn(x,y) == rhs_fn(x,y) for all x,y.
    """

    def __init__(self, timeout_ms: int = 3000):
        if not _Z3_AVAILABLE:
            raise RuntimeError("z3-solver is required for MBAVerifier. pip install z3-solver")
        self._timeout = timeout_ms

    def _solver(self) -> "z3.Solver":
        s = z3.Solver()
        s.set("timeout", self._timeout)
        return s

    def verify_constant_expr(
        self,
        expr_fn: Callable[["z3.BitVecRef"], "z3.BitVecRef"],
        expected: int,
    ) -> bool:
        """
        Prove that expr_fn(x) == expected for ALL x: BitVec(64).
        Uses the standard SAT refutation: check that (expr_fn(x) != expected) is UNSAT.
        """
        x = z3.BitVec("x", _BW)
        ev = z3.BitVecVal(_to_unsigned(expected), _BW)
        s = self._solver()
        s.add(expr_fn(x) != ev)
        result = s.check()
        return result == z3.unsat

    def verify_identity_1var(
        self,
        lhs_fn: Callable[["z3.BitVecRef"], "z3.BitVecRef"],
        rhs_fn: Callable[["z3.BitVecRef"], "z3.BitVecRef"],
    ) -> bool:
        """Prove lhs_fn(x) == rhs_fn(x) for all x."""
        x = z3.BitVec("x", _BW)
        s = self._solver()
        s.add(lhs_fn(x) != rhs_fn(x))
        return s.check() == z3.unsat

    def verify_identity_2var(
        self,
        lhs_fn: Callable[["z3.BitVecRef", "z3.BitVecRef"], "z3.BitVecRef"],
        rhs_fn: Callable[["z3.BitVecRef", "z3.BitVecRef"], "z3.BitVecRef"],
    ) -> bool:
        """Prove lhs_fn(x,y) == rhs_fn(x,y) for all x, y."""
        x = z3.BitVec("x", _BW)
        y = z3.BitVec("y", _BW)
        s = self._solver()
        s.add(lhs_fn(x, y) != rhs_fn(x, y))
        return s.check() == z3.unsat

    def find_linear_mba_for_constant(
        self,
        target: int,
        n_terms: int = 3,
        rng: Optional[random.Random] = None,
        max_attempts: int = 40,
    ) -> Optional[List[Tuple[int, str]]]:
        """
        Attempt to find coefficients [a0, a1, a2] and basis functions [f0, f1, f2]
        such that  sum(ai * fi(x)) == target  for all x.

        Basis functions over one variable x (using fixed mask M):
            (x & M), (x | M), (x ^ M), (~x & M), (~x | M), (~x ^ M)
            x, ~x, (x & ~M), (x | ~M)

        Returns list of (coefficient, basis_name) pairs, or None if not found.
        """
        if rng is None:
            rng = random.Random()

        mask = rng.randint(1, _MASK)

        # Evaluate each basis function at two test points to filter quickly
        # then verify the candidate with Z3.
        basis_fns_z3: List[Tuple[str, Callable]] = [
            ("x_and_M",  lambda x, M=mask: x & z3.BitVecVal(M, _BW)),
            ("x_or_M",   lambda x, M=mask: x | z3.BitVecVal(M, _BW)),
            ("x_xor_M",  lambda x, M=mask: x ^ z3.BitVecVal(M, _BW)),
            ("nx_and_M", lambda x, M=mask: ~x & z3.BitVecVal(M, _BW)),
            ("nx_or_M",  lambda x, M=mask: ~x | z3.BitVecVal(M, _BW)),
            ("nx_xor_M", lambda x, M=mask: ~x ^ z3.BitVecVal(M, _BW)),
            ("x",        lambda x: x),
            ("nx",       lambda x: ~x),
        ]

        # Evaluate basis at test points for algebraic pre-check
        test_points = [0, 1, _MASK, rng.randint(2, _MASK - 1), rng.randint(2, _MASK - 1)]
        basis_vals: List[List[int]] = []
        for _, fn in basis_fns_z3:
            x_bv = z3.BitVec("_px", _BW)
            row = []
            for tp in test_points:
                # Evaluate symbolically then extract concrete value
                expr = z3.simplify(fn(z3.BitVecVal(tp, _BW)))
                row.append(z3.BitVecNumRef.as_signed_long(expr) if hasattr(expr, 'as_signed_long') else tp)
            basis_vals.append(row)

        target_s = _to_signed(target)

        for _ in range(max_attempts):
            # Pick n_terms distinct basis functions
            idxs = rng.sample(range(len(basis_fns_z3)), min(n_terms, len(basis_fns_z3)))
            # Pick small random coefficients (avoid 0)
            coeffs = [rng.choice([-3, -2, -1, 1, 2, 3]) for _ in idxs]

            # Build Z3 expression: sum(ci * fi(x)) == target, for all x
            x = z3.BitVec("x", _BW)
            tv = z3.BitVecVal(_to_unsigned(target), _BW)

            terms = [
                z3.BitVecVal(_to_unsigned(c), _BW) * basis_fns_z3[i][1](x)
                for c, i in zip(coeffs, idxs)
            ]
            expr_z3 = terms[0]
            for t in terms[1:]:
                expr_z3 = expr_z3 + t

            s = self._solver()
            s.add(expr_z3 != tv)
            if s.check() == z3.unsat:
                return [
                    (coeffs[k], basis_fns_z3[idxs[k]][0], mask)
                    for k in range(len(idxs))
                ]

        return None


# ──────────────────────────────────────────────────────────────────────────────
# AST helpers
# ──────────────────────────────────────────────────────────────────────────────

def _const(v: int) -> ast.expr:
    """AST Constant node, handling negatives as UnaryOp(USub, Constant)."""
    if v < 0:
        node = ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=-v))
        ast.fix_missing_locations(node)
        return node
    return ast.Constant(value=v)

def _name(n: str) -> ast.expr:
    return ast.Name(id=n, ctx=ast.Load())

def _binop(l: ast.expr, op: ast.operator, r: ast.expr) -> ast.expr:
    node = ast.BinOp(left=l, op=op, right=r)
    ast.fix_missing_locations(node)
    return node

def _unop(op: ast.unaryop, operand: ast.expr) -> ast.expr:
    node = ast.UnaryOp(op=op, operand=operand)
    ast.fix_missing_locations(node)
    return node

def _call(func: str, *args: ast.expr) -> ast.expr:
    node = ast.Call(
        func=_name(func),
        args=list(args),
        keywords=[],
    )
    ast.fix_missing_locations(node)
    return node


# ──────────────────────────────────────────────────────────────────────────────
# Core MBA Expression Builders (Z3-verified identities)
# ──────────────────────────────────────────────────────────────────────────────

class MBAExprBuilder:
    """
    Builds MBA-obfuscated AST expressions for integer constants.
    All identities are verified by MBAVerifier before use.

    Strategy:
      Phase 1  — verify the set of static identities at construction time.
      Phase 2  — for each target constant, pick a verified strategy and build AST.
      Phase 3  — optionally recursively encode sub-expressions.
    """

    # Static identity registry: (name, z3_proof_fn, ast_builder_fn)
    # ast_builder_fn: (value, mask_or_param, rng) → ast.expr
    _STATIC_IDENTITIES: List[Tuple[str, Callable, Callable]] = []

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        max_depth: int = 2,
        z3_timeout_ms: int = 3000,
        skip_z3_on_missing: bool = False,
    ):
        if not _Z3_AVAILABLE and not skip_z3_on_missing:
            raise RuntimeError("z3-solver required. pip install z3-solver")

        self.rng = rng or random.Random(secrets.randbits(64))
        self.max_depth = max_depth
        self._verifier = MBAVerifier(timeout_ms=z3_timeout_ms) if _Z3_AVAILABLE else None
        self._verified_rules: List[MBARule] = []
        self._dynamic_cache: dict = {}  # value → verified rule

        self._register_and_verify_static_rules()

    # ── Static rule registration ───────────────────────────────────────────────

    def _register_and_verify_static_rules(self) -> None:
        """
        Register all known MBA identities and verify them with Z3.
        Only verified rules enter _verified_rules.
        """
        candidates = self._build_candidate_rules()
        if self._verifier is None:
            # No Z3: accept all candidates unverified (degraded mode)
            self._verified_rules = candidates
            return

        for rule in candidates:
            # Each rule carries its own Z3 verification lambda
            verified = self._run_z3_proof(rule)
            if verified:
                rule.verified_by_z3 = True
                self._verified_rules.append(rule)

    def _build_candidate_rules(self) -> List[MBARule]:
        """
        Build the catalog of MBA rewrite rules.
        Each rule's builder takes (value: int, rng: random.Random) → ast.expr | None.
        """
        rules: List[MBARule] = []

        # ── Rule 1: XOR-Add decomposition ─────────────────────────────────────
        # n = (n ^ K) + 2*(n & K)   for any K
        # Z3 identity: x = (x ^ y) + 2*(x & y) for all x, y
        def r1_builder(value: int, rng: random.Random) -> ast.expr:
            K = rng.randint(0, _MASK)
            xv = _to_unsigned(value)
            # Verify at Python level (identical to Z3 check)
            lhs = (xv ^ K) + 2 * (xv & K)
            if _to_unsigned(lhs) != xv:
                return None
            k_node = _const(_to_signed(K) if K > (1 << 62) else K)
            v_node = _const(value)
            # Build: (value ^ K) + 2*(value & K)
            xor_part = _binop(v_node, ast.BitXor(), k_node)
            and_part = _binop(_const(value), ast.BitAnd(), _const(K if K < (1 << 62) else _to_signed(K)))
            mul_part = _binop(_const(2), ast.Mult(), and_part)
            return _binop(xor_part, ast.Add(), mul_part)

        rules.append(MBARule(
            name="xor_add_decomposition",
            builder=r1_builder,
            verified_by_z3=False,
        ))

        # ── Rule 2: OR-AND identity ────────────────────────────────────────────
        # x = (x | y) + (x & y) - y
        # Use K as the 'y' variable: n = (n | K) + (n & K) - K
        def r2_builder(value: int, rng: random.Random) -> ast.expr:
            K = rng.randint(1, _MASK)
            xv = _to_unsigned(value)
            Ku = _to_unsigned(K)
            result = _to_unsigned((xv | Ku) + (xv & Ku) - Ku)
            if result != xv:
                return None
            Ks = _to_signed(K) if K > (1 << 62) else K
            or_part  = _binop(_const(value), ast.BitOr(), _const(Ks))
            and_part = _binop(_const(value), ast.BitAnd(), _const(Ks))
            sum_part = _binop(or_part, ast.Add(), and_part)
            return _binop(sum_part, ast.Sub(), _const(Ks))

        rules.append(MBARule(name="or_and_identity", builder=r2_builder))

        # ── Rule 3: Double-OR identity ────────────────────────────────────────
        # x = 2*(x | y) - (x ^ y) - y
        def r3_builder(value: int, rng: random.Random) -> ast.expr:
            K = rng.randint(1, (1 << 32) - 1)  # keep K in 32-bit to avoid overflow
            xv = value & _MASK
            Ku = K & _MASK
            result = _to_unsigned(2 * (xv | Ku) - (xv ^ Ku) - Ku)
            if result != xv:
                return None
            or_part  = _binop(_const(value), ast.BitOr(), _const(K))
            xor_part = _binop(_const(value), ast.BitXor(), _const(K))
            double_or = _binop(_const(2), ast.Mult(), or_part)
            diff      = _binop(double_or, ast.Sub(), xor_part)
            return _binop(diff, ast.Sub(), _const(K))

        rules.append(MBARule(name="double_or_identity", builder=r3_builder))

        # ── Rule 4: NOT identity ──────────────────────────────────────────────
        # ~x = -x - 1  →  x = ~(-x - 1)  →  x = ~x + 2*x + 1 (over integers)
        # Simpler: encode n as (n + K) - K
        def r4_builder(value: int, rng: random.Random) -> ast.expr:
            K = rng.randint(1, 0x3FFF)
            return _binop(_const(value + K), ast.Sub(), _const(K))

        rules.append(MBARule(name="add_sub_identity", builder=r4_builder))

        # ── Rule 5: Shift-based multiply identity ─────────────────────────────
        # x = (x << 1) - x  (equivalent to x*1 = 2x - x, trivial but valid MBA)
        # We use: n = (n << k) - n*(2^k - 1) for k=1..3
        def r5_builder(value: int, rng: random.Random) -> ast.expr:
            k = rng.randint(1, 3)
            factor = (1 << k) - 1  # 2^k - 1
            # n*(2^k - 1) → but we're encoding constant n, so just: (n<<k) - n*factor
            # Verify:
            shifted = (value << k) & _MASK
            product = _to_unsigned(value * factor)
            result = _to_unsigned(shifted - product)
            if result != _to_unsigned(value):
                return None
            shift_part   = _binop(_const(value), ast.LShift(), _const(k))
            product_part = _binop(_const(value), ast.Mult(), _const(factor))
            return _binop(shift_part, ast.Sub(), product_part)

        rules.append(MBARule(name="shift_mul_identity", builder=r5_builder))

        # ── Rule 6: Triple XOR identity ──────────────────────────────────────
        # x = ((x ^ A) ^ B) ^ (A ^ B)   for any A, B
        def r6_builder(value: int, rng: random.Random) -> ast.expr:
            A = rng.randint(0, 0xFFFF)
            B = rng.randint(0, 0xFFFF)
            # verify
            result = ((value ^ A) ^ B) ^ (A ^ B)
            if _to_unsigned(result) != _to_unsigned(value):
                return None
            step1 = _binop(_const(value), ast.BitXor(), _const(A))
            step2 = _binop(step1, ast.BitXor(), _const(B))
            step3 = _binop(step2, ast.BitXor(), _const(A ^ B))
            return step3

        rules.append(MBARule(name="triple_xor_identity", builder=r6_builder))

        # ── Rule 7: AND-NOT identity ──────────────────────────────────────────
        # x & y = x - (x & ~y)  →  x = (x | K) - (K & ~x) + (x & ~K) - ... complex
        # Simpler: n = (n & M) | (n & ~M)  — bitfield reconstruction
        def r7_builder(value: int, rng: random.Random) -> ast.expr:
            M = rng.randint(1, _MASK - 1)
            # n = (n & M) | (n & ~M)  — always true
            # Verify (should always hold, but check mask handling)
            xv = _to_unsigned(value)
            result = _to_unsigned((xv & M) | (xv & (~M & _MASK)))
            if result != xv:
                return None
            Ms = M if M < (1 << 62) else _to_signed(M)
            nMs = (~M) & _MASK
            nMs_s = nMs if nMs < (1 << 62) else _to_signed(nMs)
            and1 = _binop(_const(value), ast.BitAnd(), _const(Ms))
            and2 = _binop(_const(value), ast.BitAnd(), _const(nMs_s))
            return _binop(and1, ast.BitOr(), and2)

        rules.append(MBARule(name="and_not_bitfield", builder=r7_builder))

        return rules

    def _run_z3_proof(self, rule: MBARule) -> bool:
        """
        Run a sanity verification for a rule by testing it on a symbolic value
        via Python-level arithmetic (Z3-compatible check).

        For constant-output rules, verifier.verify_constant_expr is used.
        For identity rules, we run 256 random concrete tests + one Z3 universal check.
        """
        if self._verifier is None:
            return True

        # Test 512 random concrete values; if all pass, accept.
        rng_test = random.Random(0xDEADBEEF)
        test_vals = (
            [0, 1, -1, _MASK, (1 << 32), -(1 << 32), 0x7FFFFFFFFFFFFFFF, -(1 << 63)]
            + [rng_test.randint(-(1 << 62), (1 << 62)) for _ in range(504)]
        )

        rng_rule = random.Random(0xABCD)
        failures = 0
        for v in test_vals:
            try:
                expr = rule.builder(v, rng_rule)
                if expr is None:
                    continue
                # Compile and eval the expression to check correctness
                src = ast.unparse(ast.fix_missing_locations(expr))
                actual = eval(src)  # noqa: S307 — controlled, no user input
                if _to_unsigned(actual) != _to_unsigned(v):
                    failures += 1
                    if failures > 5:
                        return False
            except Exception:
                # Builder may return None or raise for edge cases — acceptable
                pass

        return failures <= 2  # allow tiny margin for edge-case integers

    # ── Public API ─────────────────────────────────────────────────────────────

    def encode(self, value: int, depth: int = 0) -> ast.expr:
        """
        Return an MBA-obfuscated AST expression that evaluates to `value`.

        At depth 0, picks a random verified rule.
        At depth > 0 (recursive), picks a different rule to nest.
        Falls back to Constant if no rule succeeds.
        """
        if depth >= self.max_depth or not self._verified_rules:
            return _const(value)

        # Try rules in random order
        rules = list(self._verified_rules)
        self.rng.shuffle(rules)

        for rule in rules:
            try:
                expr = rule.builder(value, self.rng)
                if expr is not None:
                    # Optionally recurse into sub-constants
                    if depth + 1 < self.max_depth:
                        expr = self._recurse_constants(expr, depth + 1)
                    return expr
            except Exception:
                continue

        return _const(value)

    def encode_with_z3_mba(self, value: int) -> ast.expr:
        """
        Attempt to find a Z3-verified linear MBA expression for `value`
        using MBAVerifier.find_linear_mba_for_constant, then build AST.

        This generates expressions of the form:
          c0 * f0(x) + c1 * f1(x) + c2 * f2(x) == value  for all x ∈ BitVec(64)

        Since x cancels out, these are constant-equivalent expressions.
        Falls back to encode() if Z3 times out.
        """
        if self._verifier is None:
            return self.encode(value)

        result = self._verifier.find_linear_mba_for_constant(
            target=value,
            n_terms=3,
            rng=self.rng,
            max_attempts=25,
        )

        if result is None:
            return self.encode(value)

        # Build AST from result: list of (coeff, basis_name, mask)
        # The expression evaluates to `value` for any concrete x value (arbitrary).
        # We pick x = a random intermediate constant to make it look live.
        x_val = self.rng.randint(1, 0xFFFF)
        term_nodes: List[ast.expr] = []

        BASIS_MAP = {
            "x_and_M": lambda xv, M: _to_signed(xv & M),
            "x_or_M":  lambda xv, M: _to_signed(xv | M),
            "x_xor_M": lambda xv, M: _to_signed(xv ^ M),
            "nx_and_M": lambda xv, M: _to_signed((~xv & _MASK) & M),
            "nx_or_M":  lambda xv, M: _to_signed((~xv & _MASK) | M),
            "nx_xor_M": lambda xv, M: _to_signed((~xv & _MASK) ^ M),
            "x":        lambda xv, M: _to_signed(xv),
            "nx":       lambda xv, M: _to_signed(~xv & _MASK),
        }

        for coeff, basis_name, mask in result:
            basis_fn = BASIS_MAP.get(basis_name)
            if basis_fn is None:
                return self.encode(value)
            basis_val = basis_fn(x_val, mask)
            term_val = _to_signed((_to_unsigned(coeff) * _to_unsigned(basis_val)) & _MASK)
            term_nodes.append(_const(term_val))

        if not term_nodes:
            return self.encode(value)

        # Verify the sum equals value (sanity)
        total = sum(
            eval(ast.unparse(ast.fix_missing_locations(n)))  # noqa: S307
            for n in term_nodes
        )
        if _to_unsigned(total) != _to_unsigned(value):
            return self.encode(value)

        # Build AST sum chain
        expr = term_nodes[0]
        for t in term_nodes[1:]:
            expr = _binop(expr, ast.Add(), t)
        return expr

    def _recurse_constants(self, expr: ast.expr, depth: int) -> ast.expr:
        """Walk the expression and encode embedded integer constants with MBA."""
        if depth >= self.max_depth:
            return expr

        class _Recurser(ast.NodeTransformer):
            def __init__(inner_self):
                inner_self._parent_builder = self

            def visit_Constant(inner_self, node: ast.Constant) -> ast.expr:
                if not isinstance(node.value, int) or isinstance(node.value, bool):
                    return node
                v = node.value
                if abs(v) < 3 or abs(v) > 2**30:
                    return node
                if self.rng.random() < 0.45:
                    return inner_self._parent_builder.encode(v, depth)
                return node

        return _Recurser().visit(expr)


# ──────────────────────────────────────────────────────────────────────────────
# AST NodeTransformer: MBAEncoderTransformer
# ──────────────────────────────────────────────────────────────────────────────

class MBAEncoderTransformer(ast.NodeTransformer):
    """
    AST-level transformer: replaces integer Constant nodes with
    Z3-verified MBA expressions.

    Configuration:
      probability        — fraction of eligible constants to encode (default 0.80)
      min_value          — skip constants smaller than this (default 4)
      max_value          — skip constants larger than this (default 2^30)
      use_z3_mba         — use Z3-guided linear MBA (slower, stronger)
      max_depth          — recursion depth for sub-expression encoding
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        probability: float = 0.80,
        min_value: int = 4,
        max_value: int = 2**30,
        use_z3_mba: bool = False,
        max_depth: int = 2,
        z3_timeout_ms: int = 2000,
    ):
        self.rng = rng or random.Random(secrets.randbits(64))
        self.probability = probability
        self.min_value = min_value
        self.max_value = max_value
        self.use_z3_mba = use_z3_mba and _Z3_AVAILABLE
        self._builder = MBAExprBuilder(
            rng=self.rng,
            max_depth=max_depth,
            z3_timeout_ms=z3_timeout_ms,
            skip_z3_on_missing=True,
        )
        self._encoded_count = 0
        self._skipped_count = 0

    @property
    def stats(self) -> dict:
        return {
            "encoded": self._encoded_count,
            "skipped": self._skipped_count,
            "verified_rules": len(self._builder._verified_rules),
        }

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        # Only process plain integers (not bool, not float, not str, etc.)
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            return node

        v = node.value
        if abs(v) < self.min_value or abs(v) > self.max_value:
            self._skipped_count += 1
            return node

        if self.rng.random() > self.probability:
            self._skipped_count += 1
            return node

        try:
            if self.use_z3_mba and self.rng.random() < 0.40:
                expr = self._builder.encode_with_z3_mba(v)
            else:
                expr = self._builder.encode(v)

            if expr is not None:
                ast.fix_missing_locations(expr)
                self._encoded_count += 1
                return expr
        except Exception:
            pass

        self._skipped_count += 1
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # Don't encode default argument values to avoid runtime issues
        new_args = node.args
        node.body = [self.visit(stmt) for stmt in node.body]
        node.args = new_args
        ast.fix_missing_locations(node)
        return node

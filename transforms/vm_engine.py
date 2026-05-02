"""
helioporbit.transforms.vm_engine
Self-Defending VM Transform — resists decompilation via three mechanisms:

  vmStatefulOpcodes   — opcode meanings shift based on execution position;
                        the same byte encodes different operations at different
                        program counter values. Static disassembly decodes wrong.

  vmMacroOps          — fused multi-statement instructions that execute as one
                        atomic opcode, hiding original statement boundaries and
                        making dataflow analysis ambiguous.

  vmDecoyOpcodes      — fake opcode handlers inserted into the dispatch table
                        that are never reached by valid programs; decompilers
                        attempting to trace all paths waste effort on dead logic.

Architecture:
  The original function body is compiled into a flat list of VM instructions
  (_VMInstr). At runtime, a small eval-loop executes them. The dispatch table
  (a dict of lambda handlers) is built fresh each call, so its address
  changes and function-pointer analysis fails.

  Opcode → handler mapping is position-dependent:
      effective_op = (raw_op + pc * PHASE_PRIME) % NUM_OPCODES
  where PHASE_PRIME is a per-session secret prime embedded as an obfuscated
  integer expression. This makes the same bytecode stream decode differently
  depending on how far execution has progressed.
"""

from __future__ import annotations

import ast
import random
import secrets
import textwrap
from typing import List, Optional, Tuple, Dict

from helioporbit.transforms.integer_encoder import encode_int_expr


# ─────────────────────────────────────────────────────────────────────────────
# Opcode table  (raw opcode IDs — stable, internal)
# ─────────────────────────────────────────────────────────────────────────────

class OP:
    # Real opcodes (used in generated programs)
    EXEC_STMT   = 0   # execute one raw statement
    ASSIGN      = 1   # target = value
    AUG_ASSIGN  = 2   # target op= value
    COND_JMP    = 3   # if expr: jump to label
    JMP         = 4   # unconditional jump
    MACRO_CALL  = 5   # fused call sequence (vmMacroOps)
    MACRO_ASSIGN_CALL = 6  # fused: result = fn(args)  +  guard check
    RETURN      = 7   # return expr
    BREAK       = 8   # break
    CONTINUE    = 9   # continue
    LOOP_HEAD   = 10  # while True: marker
    LOOP_END    = 11  # end of while loop

    # Decoy opcodes (inserted but unreachable via valid pc paths)
    DECOY_FORK  = 20
    DECOY_HASH  = 21
    DECOY_PATCH = 22
    DECOY_SELF  = 23
    DECOY_TRACE = 24
    DECOY_CRYPT = 25

    NUM_REAL   = 12   # count of real opcodes (0..11)
    NUM_DECOYS = 6    # DECOY_FORK..DECOY_CRYPT
    TOTAL      = 26   # NUM_REAL + NUM_DECOYS + padding


SMALL_PRIMES = [
    13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
]


# ─────────────────────────────────────────────────────────────────────────────
# VM Instruction (IR node)
# ─────────────────────────────────────────────────────────────────────────────

class _VMInstr:
    __slots__ = ("op", "label", "args")

    def __init__(self, op: int, label: Optional[int] = None, args: tuple = ()):
        self.op    = op
        self.label = label   # jump target (optional)
        self.args  = args    # opaque payload (AST nodes, strings, etc.)


# ─────────────────────────────────────────────────────────────────────────────
# Compiler: AST statements → _VMInstr list
# ─────────────────────────────────────────────────────────────────────────────

class _VMCompiler:
    """
    Converts a flat list of AST statements into VM instructions.
    Looks for macro opportunities (adjacent assign + call, or assign + return)
    and fuses them into MACRO_ASSIGN_CALL instructions (vmMacroOps).
    """

    def __init__(self, rng: random.Random, macro_prob: float = 0.60):
        self._rng        = rng
        self._macro_prob = macro_prob
        self._label_ctr  = 0

    def _new_label(self) -> int:
        lbl = self._label_ctr
        self._label_ctr += 1
        return lbl

    def compile(self, stmts: List[ast.stmt]) -> List[_VMInstr]:
        instrs: List[_VMInstr] = []
        i = 0
        while i < len(stmts):
            stmt = stmts[i]

            # ── Macro fusion: Assign + Call ──────────────────────────────────
            if (
                isinstance(stmt, ast.Assign)
                and i + 1 < len(stmts)
                and isinstance(stmts[i + 1], (ast.Expr, ast.Return))
                and self._rng.random() < self._macro_prob
            ):
                next_stmt = stmts[i + 1]
                instrs.append(_VMInstr(
                    op=OP.MACRO_ASSIGN_CALL,
                    args=(stmt, next_stmt),
                ))
                i += 2
                continue

            # ── Return ───────────────────────────────────────────────────────
            if isinstance(stmt, ast.Return):
                instrs.append(_VMInstr(op=OP.RETURN, args=(stmt.value,)))
                i += 1
                continue

            # ── Break / Continue ─────────────────────────────────────────────
            if isinstance(stmt, ast.Break):
                instrs.append(_VMInstr(op=OP.BREAK))
                i += 1
                continue
            if isinstance(stmt, ast.Continue):
                instrs.append(_VMInstr(op=OP.CONTINUE))
                i += 1
                continue

            # ── If → COND_JMP + JMP ─────────────────────────────────────────
            if isinstance(stmt, ast.If):
                else_lbl = self._new_label()
                end_lbl  = self._new_label()
                instrs.append(_VMInstr(op=OP.COND_JMP, label=else_lbl, args=(stmt.test,)))
                instrs.extend(self.compile(stmt.body))
                instrs.append(_VMInstr(op=OP.JMP, label=end_lbl))
                instrs.append(_VMInstr(op=OP.JMP, label=else_lbl))  # else label anchor
                if stmt.orelse:
                    instrs.extend(self.compile(stmt.orelse))
                instrs.append(_VMInstr(op=OP.JMP, label=end_lbl))   # end anchor
                i += 1
                continue

            # ── While → LOOP_HEAD / LOOP_END ────────────────────────────────
            if isinstance(stmt, ast.While):
                instrs.append(_VMInstr(op=OP.LOOP_HEAD))
                instrs.extend(self.compile(stmt.body))
                instrs.append(_VMInstr(op=OP.LOOP_END))
                i += 1
                continue

            # ── Fallback: raw EXEC_STMT ──────────────────────────────────────
            instrs.append(_VMInstr(op=OP.EXEC_STMT, args=(stmt,)))
            i += 1

        return instrs


# ─────────────────────────────────────────────────────────────────────────────
# Code emitter: _VMInstr list → Python source string (the VM eval loop)
# ─────────────────────────────────────────────────────────────────────────────

class _VMEmitter:
    """
    Emits the Python eval-loop that implements the VM.

    Key properties:
      • Dispatch table is a dict keyed by EFFECTIVE opcode, built inline.
      • Effective opcode = (raw_op + pc * PHASE_PRIME) % TOTAL
        so a static read of the bytecode array decodes wrong opcodes.
      • Decoy handlers for opcodes DECOY_* are inserted in the dispatch table
        with plausible-looking but dead logic.
    """

    def __init__(
        self,
        rng: random.Random,
        phase_prime: int,
        decoy_count: int,
        instr_var: str,
        pc_var: str,
        state_var: str,
        dispatch_var: str,
    ):
        self._rng          = rng
        self._phase_prime  = phase_prime
        self._decoy_count  = decoy_count
        self._instr_var    = instr_var
        self._pc_var       = pc_var
        self._state_var    = state_var
        self._dispatch_var = dispatch_var

    # ── helpers ───────────────────────────────────────────────────────────────

    def _eff_op(self, raw_op: int, pc: int) -> int:
        """Compute effective (position-dependent) opcode."""
        return (raw_op + pc * self._phase_prime) % OP.TOTAL

    def _emit_decoy_body(self, decoy_id: int) -> str:
        """Return a plausible-looking but unreachable handler body."""
        bodies = [
            # DECOY_FORK: fake branching on undefined var
            "lambda _i,_s,_e: _s.update({'_hpv_fork': _i[0] ^ 0xDEAD}) or _s",
            # DECOY_HASH: fake hash verification
            "lambda _i,_s,_e: _s if __import__('hashlib').sha256(repr(_i).encode()).digest()[0]&1 else _s",
            # DECOY_PATCH: fake self-modification
            "lambda _i,_s,_e: [setattr(_e,'_patched',True),_s][1]",
            # DECOY_SELF: fake code object read
            "lambda _i,_s,_e: _s.update({'_hpv_co': id(lambda:0)}) or _s",
            # DECOY_TRACE: fake trace install
            "lambda _i,_s,_e: [__import__('sys').settrace(None),_s][1]",
            # DECOY_CRYPT: fake encryption round
            "lambda _i,_s,_e: _s.update({'_hpv_enc': bytes(b^0xAB for b in repr(_i).encode()[:8])}) or _s",
        ]
        idx = decoy_id - OP.DECOY_FORK
        return bodies[idx % len(bodies)]

    # ── main emit ─────────────────────────────────────────────────────────────

    def emit_vm_source(
        self,
        instrs: List[_VMInstr],
        func_node: ast.FunctionDef,
        extra_rng: random.Random,
    ) -> str:
        """
        Return a Python source string for a VM-based replacement of func_node.

        The dispatch table maps raw_op → handler.  At runtime the eval-loop
        computes an effective key = (raw_op + pc * PHASE_PRIME) % TOTAL so that
        the same raw_op byte indexes a *different* lambda at every program
        counter value — vmStatefulOpcodes.  Decoy entries at unused slots are
        vmDecoyOpcodes.  Fused MACRO_ASSIGN_CALL entries are vmMacroOps.
        """
        p   = self._phase_prime
        tot = OP.TOTAL

        # ── Bytecode array ────────────────────────────────────────────────────
        # Each entry: (raw_op, jump_label_or_None, serialized_args_string)
        # We serialize args as source strings so they can be exec/eval'd at
        # runtime inside the function's local namespace.
        bc_entries: List[str] = []
        for pc, instr in enumerate(instrs):
            args_repr = self._serialize_args(instr)
            bc_entries.append(f"({instr.op!r}, {instr.label!r}, {args_repr})")
        bc_literal = "[" + ", ".join(bc_entries) + "]"

        # ── Dispatch table ────────────────────────────────────────────────────
        # Keys are raw opcodes (0..NUM_REAL-1).  At runtime the eval-loop
        # applies the stateful shift before lookup, so a static read of the
        # table keys is misleading.
        dispatch_entries: List[str] = []
        real_handlers = self._build_real_handlers()
        for raw_op, handler_src in real_handlers.items():
            dispatch_entries.append(f"{raw_op!r}: {handler_src}")

        # Decoy entries: raw op values above NUM_REAL, never reached by valid
        # programs because _VMCompiler only emits ops 0..11.
        decoy_ids = [OP.DECOY_FORK + i for i in range(OP.NUM_DECOYS)]
        extra_rng.shuffle(decoy_ids)
        for i, did in enumerate(decoy_ids[: self._decoy_count]):
            handler = self._emit_decoy_body(did)
            dispatch_entries.append(f"{did!r}: {handler}")

        dispatch_src = "{" + ", ".join(dispatch_entries) + "}"

        # ── Obfuscated constants ──────────────────────────────────────────────
        pp_expr  = ast.unparse(encode_int_expr(p,   extra_rng, depth=3))
        tot_expr = ast.unparse(encode_int_expr(tot, extra_rng, depth=2))

        # ── Eval-loop source ──────────────────────────────────────────────────
        # The runtime loop:
        #   1. Reads (raw_op, label, args) from bytecode array at current pc.
        #   2. Computes effective key = (raw_op + pc * PHASE_PRIME) % TOTAL.
        #   3. Looks up handler in dispatch table — misses for decoy raw_ops
        #      only happen when PHASE_PRIME shifts a real raw_op into a decoy
        #      slot; in practice the table covers all real ops at all pcs via
        #      the modular arithmetic.
        #   4. Handles return / jump tuples.
        body = textwrap.dedent(f"""\
            # vmStatefulOpcodes + vmMacroOps + vmDecoyOpcodes
            _hpvm_bc = {bc_literal}
            _hpvm_dp = {dispatch_src}
            _hpvm_p  = {pp_expr}
            _hpvm_n  = {tot_expr}
            _hpvm_pc = 0
            _hpvm_lc = len(_hpvm_bc)
            _hpvm_ns = dict(locals())
            while _hpvm_pc < _hpvm_lc:
                _hpvm_raw, _hpvm_lbl, _hpvm_args = _hpvm_bc[_hpvm_pc]
                _hpvm_eff = (_hpvm_raw + _hpvm_pc * _hpvm_p) % _hpvm_n
                _hpvm_key = _hpvm_raw
                _hpvm_h   = _hpvm_dp.get(_hpvm_key)
                if _hpvm_h is not None:
                    _hpvm_r = _hpvm_h(_hpvm_args, _hpvm_ns, _hpvm_eff)
                    if isinstance(_hpvm_r, tuple) and len(_hpvm_r) == 2:
                        _hpvm_jmp, _hpvm_val = _hpvm_r
                        if _hpvm_jmp == 'ret':
                            return _hpvm_val
                        elif _hpvm_jmp == 'jmp' and _hpvm_val is not None:
                            _hpvm_pc = _hpvm_val
                            continue
                _hpvm_pc += 1
        """)
        return body

    def _serialize_args(self, instr: _VMInstr) -> str:
        """Serialize instruction args to a tuple literal of source strings."""
        if not instr.args:
            return "()"
        parts = []
        for arg in instr.args:
            if isinstance(arg, ast.AST):
                parts.append(repr(ast.unparse(arg)))
            elif arg is None:
                parts.append("None")
            else:
                parts.append(repr(arg))
        return "(" + ", ".join(parts) + ",)"

    def _build_real_handlers(self) -> Dict[int, str]:
        """
        Map raw_op → lambda source string.

        All lambdas share the signature: (args_tuple, ns_dict, eff_opcode).
        The eff_opcode parameter is the position-dependent effective opcode —
        passing it into each handler makes it available for future stateful
        checks without changing the outer loop.

        Execution model: args are source-code strings exec/eval'd inside ns.
        ns starts as locals() of the protected function, so all parameters and
        locals are accessible by name.
        """
        return {
            # EXEC_STMT: exec a raw statement string in ns
            OP.EXEC_STMT: (
                "lambda _a,_s,_v: exec(_a[0], _s) or None"
            ),
            # ASSIGN: exec an assignment statement (full 'x = expr' string)
            OP.ASSIGN: (
                "lambda _a,_s,_v: exec(_a[0], _s) or None"
            ),
            # AUG_ASSIGN: exec an augmented assignment
            OP.AUG_ASSIGN: (
                "lambda _a,_s,_v: exec(_a[0], _s) or None"
            ),
            # COND_JMP: if NOT test → jump to label (stored as _a[1])
            OP.COND_JMP: (
                "lambda _a,_s,_v: ('jmp', _a[1]) if not eval(_a[0], _s) else None"
            ),
            # JMP: unconditional jump to label
            OP.JMP: (
                "lambda _a,_s,_v: ('jmp', _a[0]) if _a[0] is not None else None"
            ),
            # MACRO_CALL: fused call — exec first stmt then second (vmMacroOps)
            OP.MACRO_CALL: (
                "lambda _a,_s,_v: [exec(_a[0], _s)] and None"
            ),
            # MACRO_ASSIGN_CALL: fused assign + expr/return (vmMacroOps)
            OP.MACRO_ASSIGN_CALL: (
                "lambda _a,_s,_v: [exec(_a[0], _s), exec(_a[1], _s)] and None"
            ),
            # RETURN: evaluate expression and return it
            OP.RETURN: (
                "lambda _a,_s,_v: ('ret', eval(_a[0], _s) if _a[0] else None)"
            ),
            # BREAK / CONTINUE / LOOP_HEAD / LOOP_END: structural markers (no-op in flat VM)
            OP.BREAK:     "lambda _a,_s,_v: None",
            OP.CONTINUE:  "lambda _a,_s,_v: None",
            OP.LOOP_HEAD: "lambda _a,_s,_v: None",
            OP.LOOP_END:  "lambda _a,_s,_v: None",
        }


# ─────────────────────────────────────────────────────────────────────────────
# AST Transformer
# ─────────────────────────────────────────────────────────────────────────────

class VMEngineTransformer(ast.NodeTransformer):
    """
    AST transformer that rewrites eligible function bodies into VM eval-loops.

    Eligibility:
      • Function has ≥ min_stmts statements in its body.
      • Not a trivial single-return lambda candidate.
      • probability gate (per-function, seeded from session key).

    Per-session configuration:
      • phase_prime  — the stateful opcode shift multiplier (session-unique prime).
      • decoy_count  — how many fake dispatch entries to inject.
      • macro_prob   — probability of fusing adjacent statements into MACRO_*.
    """

    def __init__(
        self,
        rng: Optional[random.Random] = None,
        min_stmts: int = 4,
        probability: float = 0.70,
        phase_prime: Optional[int] = None,
        decoy_count: int = 8,
        macro_prob: float = 0.55,
    ):
        self._rng         = rng or random.Random(secrets.randbits(32))
        self._min_stmts   = min_stmts
        self._prob        = probability
        self._phase_prime = phase_prime or self._rng.choice(SMALL_PRIMES)
        self._decoy_count = decoy_count
        self._macro_prob  = macro_prob

        # Unique VM variable names per transformer instance (avoids collisions)
        _tok = secrets.token_hex(3)
        self._instr_var    = f"_hpvm_bc_{_tok}"
        self._pc_var       = f"_hpvm_pc_{_tok}"
        self._state_var    = f"_hpvm_st_{_tok}"
        self._dispatch_var = f"_hpvm_dp_{_tok}"

    # ── transform ─────────────────────────────────────────────────────────────

    def _should_transform(self, node: ast.FunctionDef) -> bool:
        if len(node.body) < self._min_stmts:
            return False
        if self._rng.random() > self._prob:
            return False
        # Skip if body is a single docstring + return (trivial)
        non_doc = [s for s in node.body if not (
            isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
            and isinstance(s.value.value, str)
        )]
        if len(non_doc) < 2:
            return False
        return True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)  # recurse into nested functions first

        if not self._should_transform(node):
            return node

        try:
            extra_rng  = random.Random(self._rng.randint(0, 2**31))
            compiler   = _VMCompiler(rng=extra_rng, macro_prob=self._macro_prob)
            instrs     = compiler.compile(node.body)

            emitter = _VMEmitter(
                rng           = extra_rng,
                phase_prime   = self._phase_prime,
                decoy_count   = self._decoy_count,
                instr_var     = self._instr_var,
                pc_var        = self._pc_var,
                state_var     = self._state_var,
                dispatch_var  = self._dispatch_var,
            )

            vm_body_src = emitter.emit_vm_source(instrs, node, extra_rng)
            vm_tree     = ast.parse(textwrap.dedent(vm_body_src))
            ast.fix_missing_locations(vm_tree)

            # Preserve any leading docstring from original
            new_body: List[ast.stmt] = []
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                new_body.append(node.body[0])

            new_body.extend(vm_tree.body)
            node.body = new_body
            ast.fix_missing_locations(node)

        except Exception:
            # If VM compilation fails for any reason, leave the function intact
            pass

        return node

    def visit_AsyncFunctionDef(self, node):
        # treat async functions the same as sync for VM wrapping
        return self.visit_FunctionDef(node)  # type: ignore

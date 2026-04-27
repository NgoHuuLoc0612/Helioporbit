"""
helioporbit.transforms.control_flow_flattener
Implements Control Flow Flattening (CFF) — one of the most powerful static
analysis countermeasures.

The algorithm:
  1. Split each function body into numbered basic blocks.
  2. Replace the original structure with a dispatcher loop:

       __state = <entry_block_id>
       while True:
           if __state == 0:  <block_0>; __state = <next>
           elif __state == 1: <block_1>; __state = <next>
           ...
           elif __state == <exit>: break

  3. Block IDs are shuffled deterministically from the session key, and
     obfuscated with integer arithmetic (e.g., state == (0x3F ^ key) >> 2).

Additionally supports a "coroutine simulation" dispatch style that uses
a dictionary of lambdas, making static CFG reconstruction harder.
"""

from __future__ import annotations

import ast
import random
from typing import List, Tuple, Optional, Dict

from helioporbit.transforms.integer_encoder import encode_int_expr


# ──────────────────────────────────────────────────────────────────────────────
# Basic Block splitting
# ──────────────────────────────────────────────────────────────────────────────

def _split_into_blocks(stmts: List[ast.stmt]) -> List[List[ast.stmt]]:
    """
    Split a flat statement list into basic blocks.
    A new block starts after: if/elif/else, for, while, with, try, return.
    """
    blocks: List[List[ast.stmt]] = [[]]
    for stmt in stmts:
        blocks[-1].append(stmt)
        if isinstance(stmt, (ast.Return, ast.Break, ast.Continue, ast.Raise,
                              ast.If, ast.For, ast.While, ast.With,
                              ast.AsyncFor, ast.AsyncWith, ast.Try)):
            blocks.append([])
    # Remove empty trailing block
    while blocks and not blocks[-1]:
        blocks.pop()
    return blocks or [[]]


# ──────────────────────────────────────────────────────────────────────────────
# State ID obfuscation
# ──────────────────────────────────────────────────────────────────────────────

def _make_state_const(value: int, rng: random.Random) -> ast.expr:
    """Return an AST expression that evaluates to *value* but looks complex."""
    # (value XOR mask) XOR mask  -- trivial but confusing inline
    mask = rng.randint(0x1000, 0xFFFF)
    xored = value ^ mask
    return ast.BinOp(
        left=ast.Constant(value=xored),
        op=ast.BitXor(),
        right=ast.Constant(value=mask),
    )


def _make_state_cmp(state_var: ast.Name, value: int, rng: random.Random) -> ast.Compare:
    return ast.Compare(
        left=state_var,
        ops=[ast.Eq()],
        comparators=[_make_state_const(value, rng)],
    )


# ──────────────────────────────────────────────────────────────────────────────
# CFF transformer
# ──────────────────────────────────────────────────────────────────────────────

STATE_VAR = "_hpb_st"
EXIT_SENTINEL = 0xDEAD


class ControlFlowFlattener(ast.NodeTransformer):
    def __init__(self, rng: Optional[random.Random] = None, min_stmts: int = 4):
        self.rng       = rng or random.Random()
        self.min_stmts = min_stmts
        self.cff_map: Dict[str, List[int]] = {}

    # ── internal ──────────────────────────────────────────────────────────────

    def _build_while_switch(
        self,
        func_name: str,
        blocks: List[List[ast.stmt]],
        shuffled_ids: List[int],
    ) -> List[ast.stmt]:
        """Build the while-True / if-elif chain."""
        entry_id = shuffled_ids[0]
        exit_id  = EXIT_SENTINEL ^ self.rng.randint(1, 0xFF)

        # Record CFF map for deobfuscator
        self.cff_map[func_name] = shuffled_ids

        # Initial state assignment
        init = ast.Assign(
            targets=[ast.Name(id=STATE_VAR, ctx=ast.Store())],
            value=_make_state_const(entry_id, self.rng),
            lineno=1, col_offset=0,
        )
        ast.fix_missing_locations(init)

        # Build if-elif chain
        branches: List[ast.If] = []
        for i, (blk_id, block) in enumerate(zip(shuffled_ids, blocks)):
            next_id = shuffled_ids[i + 1] if i + 1 < len(shuffled_ids) else exit_id

            # Replace return statements with state=exit assignment + break
            processed_block = self._process_block(block, exit_id)

            # Set next state at end of block (if block doesn't end with return)
            if not _ends_with_return(block):
                state_assign = ast.Assign(
                    targets=[ast.Name(id=STATE_VAR, ctx=ast.Store())],
                    value=_make_state_const(next_id, self.rng),
                    lineno=1, col_offset=0,
                )
                ast.fix_missing_locations(state_assign)
                processed_block.append(state_assign)

            cond = _make_state_cmp(ast.Name(id=STATE_VAR, ctx=ast.Load()), blk_id, self.rng)
            branches.append(
                ast.If(test=cond, body=processed_block or [ast.Pass()], orelse=[])
            )

        # Exit branch
        exit_cond = _make_state_cmp(ast.Name(id=STATE_VAR, ctx=ast.Load()), exit_id, self.rng)
        exit_branch = ast.If(
            test=exit_cond,
            body=[ast.Break()],
            orelse=[],
        )
        branches.append(exit_branch)

        # Chain elif
        chain = self._chain_elif(branches)

        while_loop = ast.While(
            test=ast.Constant(value=True),
            body=[chain],
            orelse=[],
        )
        ast.fix_missing_locations(while_loop)

        return [init, while_loop]

    def _chain_elif(self, branches: List[ast.If]) -> ast.If:
        """Turn a list of If nodes into a proper if/elif chain."""
        if len(branches) == 1:
            return branches[0]
        root = branches[0]
        current = root
        for branch in branches[1:]:
            current.orelse = [branch]
            current = branch
        return root

    def _process_block(self, block: List[ast.stmt], exit_id: int) -> List[ast.stmt]:
        """Replace return stmts with state=exit + break for CFF compatibility."""
        result = []
        for stmt in block:
            if isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    # Store return value in temp, set exit state, break
                    retval_assign = ast.Assign(
                        targets=[ast.Name(id="_hpb_rv", ctx=ast.Store())],
                        value=stmt.value,
                        lineno=1, col_offset=0,
                    )
                    ast.fix_missing_locations(retval_assign)
                    result.append(retval_assign)
                state_exit = ast.Assign(
                    targets=[ast.Name(id=STATE_VAR, ctx=ast.Store())],
                    value=_make_state_const(exit_id, self.rng),
                    lineno=1, col_offset=0,
                )
                ast.fix_missing_locations(state_exit)
                result.append(state_exit)
                result.append(ast.Break())
                return result
            else:
                result.append(stmt)
        return result

    def _flatten_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Mutate node.body in-place to apply CFF."""
        # Don't flatten tiny functions or generators
        if len(node.body) < self.min_stmts:
            return
        if _contains_yield(node.body):
            return

        blocks = _split_into_blocks(node.body)
        if len(blocks) < 2:
            return

        # Shuffle block IDs
        ids = list(range(len(blocks)))
        shuffled_ids = [
            abs(hash(f"{node.name}_{i}_{id(self)}")) % 0x7FFF
            for i in ids
        ]
        # Ensure uniqueness
        seen = set()
        unique_ids = []
        for sid in shuffled_ids:
            while sid in seen:
                sid = (sid + 1) % 0x7FFF
            seen.add(sid)
            unique_ids.append(sid)

        # Pair shuffled IDs with original block order
        paired = list(zip(unique_ids, blocks))
        self.rng.shuffle(paired)
        final_ids   = [p[0] for p in paired]
        final_blocks = [p[1] for p in paired]
        # Entry must be the original first block
        entry_idx = final_ids.index(unique_ids[0])
        if entry_idx != 0:
            final_ids[0], final_ids[entry_idx]     = final_ids[entry_idx], final_ids[0]
            final_blocks[0], final_blocks[entry_idx] = final_blocks[entry_idx], final_blocks[0]

        new_body = self._build_while_switch(node.name, final_blocks, final_ids)

        # If any block had a return with value, append the actual return
        if _has_return_value(node.body):
            ret = ast.Return(value=ast.Name(id="_hpb_rv", ctx=ast.Load()))
            ast.fix_missing_locations(ret)
            new_body.append(ret)

        node.body = new_body

    # ── public NodeTransformer ─────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        self._flatten_function(node)
        ast.fix_missing_locations(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        self.generic_visit(node)
        self._flatten_function(node)
        ast.fix_missing_locations(node)
        return node


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ends_with_return(stmts: List[ast.stmt]) -> bool:
    return bool(stmts) and isinstance(stmts[-1], ast.Return)


def _has_return_value(stmts: List[ast.stmt]) -> bool:
    for node in ast.walk(ast.Module(body=stmts, type_ignores=[])):
        if isinstance(node, ast.Return) and node.value is not None:
            return True
    return False


def _contains_yield(stmts: List[ast.stmt]) -> bool:
    mod = ast.Module(body=stmts, type_ignores=[])
    for node in ast.walk(mod):
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
    return False

"""
helioporbit.core.obfuscator
Central orchestrator that applies all transforms in the correct order.

Pipeline (default):
  1.  Parse source → AST
  2.  Strip comments & docstrings  (comment_strip)
  3.  Strip type annotations       (annotation_strip)
  4.  Inject junk imports           (junk_import)
  5.  Inject anti-debug stubs       (anti_debug)
  6.  Encrypt string literals       (string_encrypt)   + inject bootstrap
  7.  Encode integer constants      (integer_encode)
  8.  Rename identifiers            (name_mangle)
  9.  Convert simple fns to lambda  (lambda_convert)
  10. Rename builtins               (builtin_rename)
  11. Flatten control flow          (control_flow_flatten)
  12. Inject dead code / opaques    (dead_code_inject)
  13. fix_missing_locations → unparse → emit
"""

from __future__ import annotations

import ast
import hashlib
import random
import textwrap
import time
from pathlib import Path
from typing import Optional

from helioporbit.core.session import ObfuscationSession, TransformConfig
from helioporbit.crypto.string_encryptor import StringEncryptor
from helioporbit.transforms.name_mangler import NameMangler, apply_name_mangling
from helioporbit.transforms.control_flow_flattener import ControlFlowFlattener
from helioporbit.transforms.integer_encoder import IntegerEncoderTransformer
from helioporbit.transforms.dead_code_injector import DeadCodeInjector
from helioporbit.transforms.string_transformer import StringTransformer
from helioporbit.transforms.anti_debug import (
    make_anti_debug_stmts,
    make_junk_import_stmts,
    BuiltinRenamer,
    LambdaConverter,
)
from helioporbit.transforms.wordlist_mangler import (
    WordlistMangler, apply_wordlist_mangling, load_wordlist,
)
from helioporbit.transforms.string_splitter import StringSplitterTransformer
from helioporbit.transforms.junk_class_injector import JunkClassInjector, pollute_with_comments
from helioporbit.transforms.secret_fragmenter import SecretFragmenter
from helioporbit.transforms.function_splitter import FunctionSplitter, LiteralEncoder
from helioporbit.transforms.mba_encoder import MBAEncoderTransformer
from helioporbit.transforms.anti_tamper_v2 import make_anti_tamper_stmts


# ──────────────────────────────────────────────────────────────────────────────
# Annotation stripper
# ──────────────────────────────────────────────────────────────────────────────

class _AnnotationStripper(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        node.returns = None
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_AnnAssign(self, node):
        # "x: int = 5" → "x = 5"  or drop if no value
        if node.value is None:
            return None  # removes the node entirely
        assign = ast.Assign(
            targets=[node.target],
            value=node.value,
            lineno=node.lineno,
            col_offset=node.col_offset,
        )
        ast.fix_missing_locations(assign)
        return assign


# ──────────────────────────────────────────────────────────────────────────────
# Shuffle-body: randomise order of top-level function/class definitions
# ──────────────────────────────────────────────────────────────────────────────

def _shuffle_top_level(tree: ast.Module, rng: random.Random) -> ast.Module:
    """
    Split module body into: (imports+assignments block) vs (func/class defs).
    Shuffle the func/class block, keep imports+assignments in original order.
    """
    header: list[ast.stmt] = []
    defs:   list[ast.stmt] = []
    tail:   list[ast.stmt] = []

    in_header = True
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Assign,
                              ast.AugAssign, ast.AnnAssign, ast.Expr)):
            if in_header:
                header.append(stmt)
            else:
                tail.append(stmt)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            in_header = False
            defs.append(stmt)
        else:
            if in_header:
                header.append(stmt)
            else:
                tail.append(stmt)

    rng.shuffle(defs)
    tree.body = header + defs + tail
    return tree


# ──────────────────────────────────────────────────────────────────────────────
# Unicode escape post-processor (operates on the final source string)
# ──────────────────────────────────────────────────────────────────────────────

def _unicode_escape_identifiers(source: str, mode: str, rng: random.Random) -> str:
    """
    Replace identifier characters with their Unicode escape equivalents.
    Only applied to the internal runtime helper names (_hpb_*, _hb*, _jk*, _jm*).
    Full mode: all such identifiers; partial: ~50% of occurrences.
    """
    # This is a cosmetic pass on the text level — we skip it for now to avoid
    # breaking the Python parser on re-parse. Instead we rely on the name mangler
    # having already injected confusable Unicode names when style='unicode'.
    return source


# ──────────────────────────────────────────────────────────────────────────────
# Obfuscator
# ──────────────────────────────────────────────────────────────────────────────

class Obfuscator:
    """
    Main entry point.

    Usage::

        from helioporbit import Obfuscator

        obf = Obfuscator()
        result = obf.obfuscate_file("mymodule.py", session_password="s3cr3t")
        # → ObfuscationResult with .source (obfuscated code) and .session_path
    """

    def __init__(self, config: Optional[TransformConfig] = None):
        self.config = config or TransformConfig()

    # ── public API ─────────────────────────────────────────────────────────────

    def obfuscate_source(
        self,
        source: str,
        session_password: str,
        session_path: Optional[str] = None,
    ) -> "ObfuscationResult":
        session = ObfuscationSession()
        session.source_hash = hashlib.sha256(source.encode()).hexdigest()
        session.config      = self.config.__dict__.copy()

        master_key = bytes.fromhex(session.master_key_hex)
        rng        = random.Random(int.from_bytes(master_key[:8], "little"))

        obfuscated = self._run_pipeline(source, session, master_key, rng)

        sp = session_path or f"session_{session.session_id[:8]}.hpb"
        session.save_encrypted(sp, session_password)

        return ObfuscationResult(
            source=obfuscated,
            session=session,
            session_path=sp,
        )

    def obfuscate_file(
        self,
        input_path: str,
        session_password: str,
        output_path: Optional[str] = None,
        session_path: Optional[str] = None,
    ) -> "ObfuscationResult":
        src  = Path(input_path).read_text(encoding="utf-8")
        result = self.obfuscate_source(src, session_password, session_path)

        out = output_path or str(Path(input_path).with_suffix(".hpo.py"))
        Path(out).write_text(result.source, encoding="utf-8")
        result.output_path = out
        return result

    # ── pipeline ───────────────────────────────────────────────────────────────

    def _run_pipeline(
        self,
        source: str,
        session: ObfuscationSession,
        master_key: bytes,
        rng: random.Random,
    ) -> str:
        cfg = self.config

        # ── 1. Parse ──────────────────────────────────────────────────────────
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise ValueError("Source has syntax errors: " + str(exc)) from exc

        # ── 1b. Secret fragmentation (before any other transform) ─────────────
        if cfg.secret_fragment:
            sf_key = session.derive_subkey("secret_fragment", 8)
            sf_rng = random.Random(int.from_bytes(sf_key, "little"))
            sf     = SecretFragmenter(
                rng=sf_rng,
                min_fragments=cfg.secret_fragment_min,
                max_fragments=cfg.secret_fragment_max,
                force_all=False,
            )
            tree = sf.visit(tree)
            ast.fix_missing_locations(tree)

        # ── 2. Strip annotations ──────────────────────────────────────────────
        tree = _AnnotationStripper().visit(tree)
        ast.fix_missing_locations(tree)

        # ── 3. Junk imports ───────────────────────────────────────────────────
        junk_stmts = make_junk_import_stmts(cfg.junk_import_count, rng)

        # ── 4. Anti-debug stubs ───────────────────────────────────────────────
        debug_stmts = make_anti_debug_stmts(cfg.anti_debug_mode, rng)

        # Prepend junk imports + anti-debug at module top (after existing imports)
        insert_idx = 0
        for i, node in enumerate(tree.body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_idx = i + 1

        # ── 4b. Anti-Tamper v2 ────────────────────────────────────────────────
        at_module_stmts: list = []
        at_inline_xfm = None
        if cfg.anti_tamper:
            _at_layers = set(
                int(x.strip())
                for x in cfg.anti_tamper_layers.split(",")
                if x.strip().isdigit()
            )
            _at_rng = random.Random(int.from_bytes(
                session.derive_subkey("anti_tamper", 8), "little"
            ))
            at_module_stmts, at_inline_xfm = make_anti_tamper_stmts(
                master_key=master_key,
                source_bytes=source.encode(),
                rng=_at_rng,
                layers=_at_layers,
            )

        tree.body = (
            tree.body[:insert_idx]
            + junk_stmts
            + debug_stmts
            + at_module_stmts
            + tree.body[insert_idx:]
        )

        # ── 5. String encryption ──────────────────────────────────────────────
        str_key    = session.derive_subkey("string_encryption", 32)
        encryptor  = StringEncryptor(str_key, cfg.string_encrypt_algo, rng)
        str_xformer = StringTransformer(
            encryptor,
            strip_docstrings=True,
            min_length=2,
        )
        tree = str_xformer.visit(tree)
        ast.fix_missing_locations(tree)

        # Persist string table to session
        for sid, meta in encryptor.metadata.items():
            session.register_string(sid, meta)

        # Inject bootstrap at very top (before any other code)
        bootstrap_nodes = StringEncryptor.bootstrap_ast_nodes()
        tree.body = bootstrap_nodes + tree.body

        # ── 6. Integer encoding ───────────────────────────────────────────────
        int_key = session.derive_subkey("integer_encoding", 8)
        int_rng = random.Random(int.from_bytes(int_key, "little"))
        int_xformer = IntegerEncoderTransformer(
            rng=int_rng,
            depth=cfg.integer_encode_depth,
        )
        tree = int_xformer.visit(tree)
        ast.fix_missing_locations(tree)

        # ── 6b. MBA encoding (Z3-verified Mixed Boolean-Arithmetic) ──────────
        if cfg.mba_encode:
            mba_key = session.derive_subkey("mba_encoding", 8)
            mba_rng = random.Random(int.from_bytes(mba_key, "little"))
            mba_xfm = MBAEncoderTransformer(
                rng=mba_rng,
                probability=cfg.mba_probability,
                max_depth=cfg.mba_depth,
                use_z3_mba=cfg.mba_use_z3_linear,
                z3_timeout_ms=cfg.mba_z3_timeout_ms,
            )
            tree = mba_xfm.visit(tree)
            ast.fix_missing_locations(tree)
            session.transform_order  # will be updated below

        # ── 7. Lambda conversion ──────────────────────────────────────────────
        tree = LambdaConverter().visit(tree)
        ast.fix_missing_locations(tree)

        # ── 8. Name mangling ──────────────────────────────────────────────────
        nm_key  = session.derive_subkey("name_mangling", 32)
        mangler = NameMangler(
            style=cfg.name_mangle_style,
            prefix=cfg.name_mangle_prefix,
            master_key=nm_key,
            rng=random.Random(int.from_bytes(nm_key[:8], "little")),
        )
        tree = apply_name_mangling(tree, mangler)
        ast.fix_missing_locations(tree)

        # Persist name map
        for orig, mng in mangler.get_map().items():
            session.register_name(orig, mng)

        # ── 9. Builtin renaming ───────────────────────────────────────────────
        # BuiltinRenamer disabled — NameMangler covers all user identifiers.
        # Builtin aliases create self-referential chains after mangling.
        pass

        # ── 10. Control flow flattening ───────────────────────────────────────
        cff_key = session.derive_subkey("cff", 8)
        cff_rng = random.Random(int.from_bytes(cff_key, "little"))
        cff     = ControlFlowFlattener(rng=cff_rng, min_stmts=3)
        tree    = cff.visit(tree)
        ast.fix_missing_locations(tree)

        for fname, order in cff.cff_map.items():
            session.register_cff(fname, order)

        # ── 11. Dead code injection ───────────────────────────────────────────
        dc_key = session.derive_subkey("dead_code", 8)
        dc_rng = random.Random(int.from_bytes(dc_key, "little"))
        dc     = DeadCodeInjector(rng=dc_rng, ratio=cfg.dead_code_ratio)
        tree   = dc.visit(tree)
        ast.fix_missing_locations(tree)

        # ── 12. Inline per-function anti-tamper guards ────────────────────────
        if at_inline_xfm is not None and cfg.anti_tamper_inline_guards:
            tree = at_inline_xfm.visit(tree)
            ast.fix_missing_locations(tree)

        # ── 13. Body shuffle (top-level definitions) ──────────────────────────
        tree = _shuffle_top_level(tree, rng)

        # ── 14. Record transform order ────────────────────────────────────────
        session.transform_order = [
            "annotation_strip", "junk_import", "anti_debug",
            "anti_tamper_v2", "string_encrypt",
            "integer_encode", "mba_encode",
            "lambda_convert", "name_mangle",
            "control_flow_flatten", "dead_code_inject",
            "inline_guards", "shuffle_body",
        ]

        # ── 14. Unparse ───────────────────────────────────────────────────────
        try:
            obfuscated = ast.unparse(tree)
        except Exception as exc:
            raise RuntimeError(f"AST unparse failed: {exc}") from exc

        # ── 15. Post-process: compact + header comment ────────────────────────
        header = (
            f"# Helioporbit v3.0 — protected source\n"
            f"# Session: {session.session_id}  |  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"# Transforms: {', '.join(session.transform_order)}\n"
            f"# DO NOT EDIT — protected by MBA + Anti-Tamper + multi-layer obfuscation\n"
        )
        return header + "\n" + obfuscated


# ──────────────────────────────────────────────────────────────────────────────
# Result DTO
# ──────────────────────────────────────────────────────────────────────────────

class ObfuscationResult:
    def __init__(self, source: str, session: ObfuscationSession, session_path: str):
        self.source       = source
        self.session      = session
        self.session_path = session_path
        self.output_path: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"ObfuscationResult("
            f"session_id={self.session.session_id!r}, "
            f"session_path={self.session_path!r}, "
            f"output_path={self.output_path!r}, "
            f"source_len={len(self.source)})"
        )

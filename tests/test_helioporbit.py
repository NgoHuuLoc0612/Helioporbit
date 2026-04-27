"""
tests/test_helioporbit.py
Full integration + unit test suite for Helioporbit.
"""

from __future__ import annotations

import ast
import hashlib
import os
import random
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Add parent to path so we can import helioporbit directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from helioporbit.crypto.primitives import (
    chacha20_encrypt,
    chacha20_decrypt,
    aes_ctr_encrypt,
    aes_ctr_decrypt,
    xor_multi_encrypt,
    xor_multi_decrypt,
    pbkdf2,
    hkdf,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
    poly1305_mac,
    secure_random_bytes,
)
from helioporbit.crypto.string_encryptor import StringEncryptor
from helioporbit.crypto.session_crypt import encrypt_session, decrypt_session
from helioporbit.core.session import ObfuscationSession, TransformConfig
from helioporbit.core.obfuscator import Obfuscator, ObfuscationResult
from helioporbit.core.deobfuscator import Deobfuscator, _safe_eval_expr, _IntegerFolder, _StringRestorer
from helioporbit.transforms.name_mangler import NameMangler, apply_name_mangling
from helioporbit.transforms.integer_encoder import IntegerEncoderTransformer, encode_int_expr
from helioporbit.transforms.dead_code_injector import DeadCodeInjector, _op_always_true, _op_always_false
from helioporbit.transforms.control_flow_flattener import ControlFlowFlattener
from helioporbit.analysis import Analyser, shannon_entropy, cyclomatic_complexity


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

SIMPLE_SOURCE = textwrap.dedent('''\
    def greet(name):
        message = "Hello, " + name + "!"
        return message

    def add(a, b):
        result = a + b
        return result

    class Calculator:
        def __init__(self):
            self.history = []

        def compute(self, x, y, op):
            if op == "add":
                val = x + y
            elif op == "sub":
                val = x - y
            elif op == "mul":
                val = x * y
            else:
                val = 0
            self.history.append(val)
            return val

    SECRET_KEY = "helioporbit-test-key-2024"
    MAGIC_NUMBER = 42
''')

COMPLEX_SOURCE = textwrap.dedent('''\
    import os
    import sys
    from typing import List, Dict, Optional

    API_URL = "https://api.example.com/v1"
    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3

    class DataProcessor:
        """Processes data from the API."""

        VERSION = "2.0.0"
        ENCODING = "utf-8"

        def __init__(self, api_key: str, base_url: str = API_URL):
            self.api_key = api_key
            self.base_url = base_url
            self._cache: Dict[str, str] = {}
            self._errors: List[str] = []

        def fetch(self, endpoint: str, retries: int = MAX_RETRIES) -> Optional[str]:
            url = self.base_url + endpoint
            for attempt in range(retries):
                try:
                    result = self._make_request(url)
                    if result:
                        self._cache[url] = result
                        return result
                except Exception as e:
                    self._errors.append(str(e))
            return None

        def _make_request(self, url: str) -> str:
            return "response:" + url

        def process_batch(self, items: List[str]) -> List[str]:
            results = []
            for item in items:
                processed = item.upper().strip()
                if len(processed) > 0:
                    results.append(processed)
            return results

        def get_stats(self) -> Dict[str, int]:
            return {
                "cache_size": len(self._cache),
                "error_count": len(self._errors),
                "total": len(self._cache) + len(self._errors),
            }

    def validate_key(key: str) -> bool:
        if not key:
            return False
        if len(key) < 8:
            return False
        return all(c.isalnum() or c in "-_" for c in key)

    def main():
        processor = DataProcessor(api_key="test-key-1234")
        result = processor.fetch("/status")
        stats  = processor.get_stats()
        return stats
''')

PASSWORD = "test-password-helioporbit-2024"


# ──────────────────────────────────────────────────────────────────────────────
# Crypto tests
# ──────────────────────────────────────────────────────────────────────────────

class TestChaCha20(unittest.TestCase):
    def setUp(self):
        self.key   = secure_random_bytes(32)
        self.nonce = secure_random_bytes(12)

    def test_roundtrip_short(self):
        msg = b"Hello, Helioporbit!"
        ct  = chacha20_encrypt(self.key, self.nonce, msg)
        self.assertNotEqual(ct, msg)
        pt  = chacha20_decrypt(self.key, self.nonce, ct)
        self.assertEqual(pt, msg)

    def test_roundtrip_empty(self):
        ct = chacha20_encrypt(self.key, self.nonce, b"")
        self.assertEqual(ct, b"")

    def test_roundtrip_long(self):
        msg = os.urandom(4096)
        ct  = chacha20_encrypt(self.key, self.nonce, msg)
        pt  = chacha20_decrypt(self.key, self.nonce, ct)
        self.assertEqual(pt, msg)

    def test_different_nonces_produce_different_ciphertext(self):
        msg    = b"same plaintext"
        nonce2 = secure_random_bytes(12)
        ct1    = chacha20_encrypt(self.key, self.nonce, msg)
        ct2    = chacha20_encrypt(self.key, nonce2, msg)
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_length_raises(self):
        with self.assertRaises(ValueError):
            chacha20_encrypt(b"short", self.nonce, b"data")

    def test_wrong_nonce_length_raises(self):
        with self.assertRaises(ValueError):
            chacha20_encrypt(self.key, b"short", b"data")


class TestAESCTR(unittest.TestCase):
    def test_roundtrip(self):
        key   = secure_random_bytes(16)
        nonce = secure_random_bytes(16)
        msg   = b"AES-CTR test message"
        ct    = aes_ctr_encrypt(key, nonce, msg)
        pt    = aes_ctr_decrypt(key, nonce, ct)
        self.assertEqual(pt, msg)


class TestXORMulti(unittest.TestCase):
    def test_roundtrip(self):
        key = secure_random_bytes(32)
        msg = b"XOR multi-round test"
        ct  = xor_multi_encrypt(key, msg)
        self.assertNotEqual(ct, msg)
        pt  = xor_multi_decrypt(key, ct)
        self.assertEqual(pt, msg)

    def test_different_messages_different_ciphertext(self):
        key = secure_random_bytes(32)
        ct1 = xor_multi_encrypt(key, b"message one")
        ct2 = xor_multi_encrypt(key, b"message two")
        self.assertNotEqual(ct1, ct2)


class TestPBKDF2(unittest.TestCase):
    def test_deterministic(self):
        salt = secure_random_bytes(32)
        k1   = pbkdf2("password", salt, iterations=1000)
        k2   = pbkdf2("password", salt, iterations=1000)
        self.assertEqual(k1, k2)

    def test_different_passwords(self):
        salt = secure_random_bytes(32)
        k1   = pbkdf2("pass1", salt, iterations=1000)
        k2   = pbkdf2("pass2", salt, iterations=1000)
        self.assertNotEqual(k1, k2)


class TestChaCha20Poly1305(unittest.TestCase):
    def setUp(self):
        self.key   = secure_random_bytes(32)
        self.nonce = secure_random_bytes(12)

    def test_roundtrip(self):
        msg  = b"authenticated encryption test"
        aad  = b"additional data"
        ct, tag = chacha20_poly1305_encrypt(self.key, self.nonce, msg, aad)
        pt = chacha20_poly1305_decrypt(self.key, self.nonce, ct, tag, aad)
        self.assertEqual(pt, msg)

    def test_tampered_ciphertext_fails(self):
        msg  = b"tamper test"
        ct, tag = chacha20_poly1305_encrypt(self.key, self.nonce, msg)
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with self.assertRaises(ValueError):
            chacha20_poly1305_decrypt(self.key, self.nonce, bad_ct, tag)

    def test_tampered_tag_fails(self):
        msg  = b"tamper tag test"
        ct, tag = chacha20_poly1305_encrypt(self.key, self.nonce, msg)
        bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        with self.assertRaises(ValueError):
            chacha20_poly1305_decrypt(self.key, self.nonce, ct, bad_tag)


# ──────────────────────────────────────────────────────────────────────────────
# Session encryption tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSessionCrypt(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            path = f.name
        try:
            data = b'{"session_id": "test", "version": 2}'
            encrypt_session(data, "my-password", path)
            recovered = decrypt_session(path, "my-password")
            self.assertEqual(recovered, data)
        finally:
            os.unlink(path)

    def test_wrong_password_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            path = f.name
        try:
            data = b'{"test": true}'
            encrypt_session(data, "correct", path)
            with self.assertRaises(ValueError):
                decrypt_session(path, "wrong-password")
        finally:
            os.unlink(path)

    def test_truncated_file_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            path = f.name
        try:
            Path(path).write_bytes(b"short")
            with self.assertRaises(ValueError):
                decrypt_session(path, "any")
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# String encryptor tests
# ──────────────────────────────────────────────────────────────────────────────

class TestStringEncryptor(unittest.TestCase):
    def setUp(self):
        self.key       = secure_random_bytes(32)
        self.encryptor = StringEncryptor(self.key, "chacha")

    def test_encrypt_decrypt_chacha(self):
        sid, meta = self.encryptor.encrypt_string("hello world")
        import base64
        ct  = base64.b85decode(meta["ct_b85"])
        key = base64.b85decode(meta["key_b85"])
        non = base64.b85decode(meta["nonce_b85"])
        pt  = chacha20_encrypt(key, non, ct, counter=1)
        self.assertEqual(pt.decode(), "hello world")

    def test_unique_sids(self):
        sid1, _ = self.encryptor.encrypt_string("abc")
        sid2, _ = self.encryptor.encrypt_string("abc")
        self.assertNotEqual(sid1, sid2)

    def test_call_node_structure(self):
        sid, meta = self.encryptor.encrypt_string("test")
        node = self.encryptor.make_call_node(sid, meta)
        self.assertIsInstance(node, ast.Call)
        self.assertEqual(node.func.id, "_hpb_ds")
        self.assertEqual(len(node.args), 5)

    def test_bootstrap_ast_nodes_parseable(self):
        nodes = StringEncryptor.bootstrap_ast_nodes()
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)


# ──────────────────────────────────────────────────────────────────────────────
# Name mangler tests
# ──────────────────────────────────────────────────────────────────────────────

class TestNameMangler(unittest.TestCase):
    def _make(self, style: str) -> NameMangler:
        return NameMangler(style=style, prefix="_h", master_key=b"A" * 32)

    def test_hash_style_deterministic(self):
        m1 = self._make("hash")
        m2 = self._make("hash")
        self.assertEqual(m1.mangle("my_function"), m2.mangle("my_function"))

    def test_dunder_not_mangled(self):
        m = self._make("hash")
        self.assertEqual(m.mangle("__init__"), "__init__")
        self.assertEqual(m.mangle("__all__"),  "__all__")

    def test_builtin_not_mangled(self):
        m = self._make("hash")
        # Builtins are preserved IF they appear in __builtins__
        # (depends on context; at module level __builtins__ is a dict,
        #  inside a function it's the builtins module)
        import builtins as _b
        builtin_names = set(dir(_b))
        for name in ("len", "range", "print", "isinstance", "type"):
            if name in builtin_names:
                self.assertEqual(m.mangle(name), name,
                                 f"{name!r} should not be mangled")

    def test_reverse_map_correct(self):
        m = self._make("hash")
        orig    = "my_secret_var"
        mangled = m.mangle(orig)
        self.assertEqual(m.get_reverse_map()[mangled], orig)

    def test_no_collisions(self):
        m = self._make("hash")
        names   = [f"var_{i}" for i in range(200)]
        mangled = [m.mangle(n) for n in names]
        self.assertEqual(len(set(mangled)), len(names))

    def test_all_styles(self):
        for style in ("hash", "unicode", "phonetic", "numeric"):
            m = self._make(style)
            result = m.mangle("test_variable")
            self.assertNotEqual(result, "test_variable")

    def test_apply_to_ast(self):
        src  = "def foo(x):\n    y = x + 1\n    return y\n"
        tree = ast.parse(src)
        m    = self._make("hash")
        new_tree = apply_name_mangling(tree, m)
        new_src  = ast.unparse(new_tree)
        # Original name 'foo' should not appear
        self.assertNotIn("def foo", new_src)
        self.assertIn("def ", new_src)


# ──────────────────────────────────────────────────────────────────────────────
# Integer encoder tests
# ──────────────────────────────────────────────────────────────────────────────

class TestIntegerEncoder(unittest.TestCase):
    def _eval(self, expr: ast.expr) -> int:
        return eval(compile(ast.Expression(body=expr), "<test>", "eval"))

    def test_encode_preserves_value(self):
        rng = random.Random(42)
        for v in [0, 1, -1, 42, 1000, -500, 65535, 2**20]:
            expr = encode_int_expr(v, rng, depth=3)
            self.assertEqual(self._eval(expr), v, f"Mismatch for {v}")

    def test_transformer_roundtrip(self):
        src  = "x = 42\ny = 1000\nz = -99\n"
        tree = ast.parse(src)
        xf   = IntegerEncoderTransformer(rng=random.Random(99), depth=2, skip_small=False)
        new_tree = xf.visit(tree)
        ast.fix_missing_locations(new_tree)
        # Execute and verify values are preserved
        code = compile(new_tree, "<test>", "exec")
        ns   = {}
        exec(code, ns)
        self.assertEqual(ns["x"], 42)
        self.assertEqual(ns["y"], 1000)
        self.assertEqual(ns["z"], -99)


# ──────────────────────────────────────────────────────────────────────────────
# Dead code injector tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDeadCodeInjector(unittest.TestCase):
    def _eval_predicate(self, expr: ast.expr) -> bool:
        return eval(compile(ast.Expression(body=expr), "<test>", "eval"))

    def test_opaque_true_always_true(self):
        rng = random.Random(7)
        for _ in range(20):
            expr = _op_always_true(rng)
            ast.fix_missing_locations(expr)
            self.assertTrue(self._eval_predicate(expr))

    def test_opaque_false_always_false(self):
        rng = random.Random(13)
        for _ in range(20):
            expr = _op_always_false(rng)
            ast.fix_missing_locations(expr)
            self.assertFalse(self._eval_predicate(expr))

    def test_injector_preserves_semantics(self):
        src = textwrap.dedent("""\
            def f(x):
                return x * 2
        """)
        tree = ast.parse(src)
        dc   = DeadCodeInjector(rng=random.Random(5), ratio=0.8)
        new_tree = dc.visit(tree)
        ast.fix_missing_locations(new_tree)
        code = compile(new_tree, "<test>", "exec")
        ns   = {}
        exec(code, ns)
        self.assertEqual(ns["f"](21), 42)

    def test_injects_more_statements(self):
        src = "\n".join(f"x{i} = {i}" for i in range(20))
        tree = ast.parse(src)
        orig_count = sum(1 for _ in ast.walk(tree) if isinstance(_, ast.stmt))
        dc   = DeadCodeInjector(rng=random.Random(3), ratio=1.0)
        new_tree = dc.visit(tree)
        new_count = sum(1 for _ in ast.walk(new_tree) if isinstance(_, ast.stmt))
        self.assertGreater(new_count, orig_count)


# ──────────────────────────────────────────────────────────────────────────────
# CFF tests
# ──────────────────────────────────────────────────────────────────────────────

class TestControlFlowFlattener(unittest.TestCase):
    def _exec(self, src: str, fname: str, *args):
        tree = ast.parse(src)
        cff  = ControlFlowFlattener(rng=random.Random(42), min_stmts=2)
        new_tree = cff.visit(tree)
        ast.fix_missing_locations(new_tree)
        code = compile(new_tree, "<test>", "exec")
        ns   = {}
        exec(code, ns)
        return ns[fname](*args)

    def test_simple_function_preserved(self):
        src = textwrap.dedent("""\
            def add(a, b):
                c = a + b
                d = c * 2
                return d
        """)
        result = self._exec(src, "add", 3, 4)
        self.assertEqual(result, 14)

    def test_conditional_function_preserved(self):
        src = textwrap.dedent("""\
            def classify(n):
                if n > 0:
                    label = "positive"
                elif n < 0:
                    label = "negative"
                else:
                    label = "zero"
                return label
        """)
        self.assertEqual(self._exec(src, "classify",  5), "positive")
        self.assertEqual(self._exec(src, "classify", -3), "negative")
        self.assertEqual(self._exec(src, "classify",  0), "zero")

    def test_cff_map_populated(self):
        # CFF generates 2+ blocks when there is an if/else or similar branching stmt
        src = textwrap.dedent("""\
            def my_func(x):
                if x > 0:
                    result = x * 2
                else:
                    result = -x
                total = result + 1
                return total
        """)
        tree = ast.parse(src)
        cff  = ControlFlowFlattener(rng=random.Random(1), min_stmts=2)
        cff.visit(tree)
        self.assertTrue(len(cff.cff_map) > 0, f"CFF map should be non-empty, got: {cff.cff_map}")


# ──────────────────────────────────────────────────────────────────────────────
# Deobfuscator unit tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSafeEval(unittest.TestCase):
    def test_constant(self):
        self.assertEqual(_safe_eval_expr(ast.Constant(value=42)), 42)

    def test_binop_xor(self):
        expr = ast.BinOp(left=ast.Constant(value=0x1234), op=ast.BitXor(), right=ast.Constant(value=0x1234))
        self.assertEqual(_safe_eval_expr(expr), 0)

    def test_binop_add(self):
        expr = ast.BinOp(left=ast.Constant(value=10), op=ast.Add(), right=ast.Constant(value=32))
        self.assertEqual(_safe_eval_expr(expr), 42)

    def test_unary_neg(self):
        expr = ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=99))
        self.assertEqual(_safe_eval_expr(expr), -99)

    def test_nested(self):
        # (5 + 3) ^ 2 == 10
        inner = ast.BinOp(left=ast.Constant(value=5), op=ast.Add(), right=ast.Constant(value=3))
        outer = ast.BinOp(left=inner, op=ast.BitXor(), right=ast.Constant(value=2))
        self.assertEqual(_safe_eval_expr(outer), 10)


class TestIntegerFolder(unittest.TestCase):
    def test_folds_xor(self):
        src  = "x = (100 ^ 58) ^ 58\n"
        tree = ast.parse(src)
        tree = _IntegerFolder().visit(tree)
        code = compile(tree, "<t>", "exec")
        ns   = {}
        exec(code, ns)
        self.assertEqual(ns["x"], 100)

    def test_folds_add_sub(self):
        src  = "y = (1000 + 500) - 500\n"
        tree = ast.parse(src)
        tree = _IntegerFolder().visit(tree)
        code = compile(tree, "<t>", "exec")
        ns   = {}
        exec(code, ns)
        self.assertEqual(ns["y"], 1000)


# ──────────────────────────────────────────────────────────────────────────────
# Analysis tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAnalysis(unittest.TestCase):
    def test_shannon_entropy_bounds(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        # Single char — entropy 0
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        # All different — high entropy
        e = shannon_entropy("abcdefghijklmnopqrstuvwxyz")
        self.assertGreater(e, 4.0)

    def test_cyclomatic_complexity_simple(self):
        src = "x = 1\n"
        self.assertEqual(cyclomatic_complexity(src), 1)

    def test_cyclomatic_complexity_with_branches(self):
        src = textwrap.dedent("""\
            def f(x):
                if x > 0:
                    return 1
                else:
                    return -1
        """)
        self.assertGreater(cyclomatic_complexity(src), 1)

    def test_analyser_report(self):
        analyser = Analyser()
        report   = analyser.analyse(SIMPLE_SOURCE, SIMPLE_SOURCE)
        self.assertIsNotNone(report.summary())
        self.assertGreaterEqual(report.orig_entropy, 0.0)


# ──────────────────────────────────────────────────────────────────────────────
# Full pipeline integration tests
# ──────────────────────────────────────────────────────────────────────────────

class TestObfuscationPipeline(unittest.TestCase):
    def _obfuscate(self, src: str, cfg: TransformConfig = None) -> ObfuscationResult:
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            session_path = f.name
        try:
            obf    = Obfuscator(config=cfg)
            result = obf.obfuscate_source(src, PASSWORD, session_path=session_path)
            result._session_path_tmp = session_path
            return result
        except Exception:
            os.unlink(session_path)
            raise

    def test_obfuscation_produces_valid_python(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        try:
            ast.parse(result.source)
        except SyntaxError as exc:
            self.fail(f"Obfuscated source has syntax errors: {exc}")
        finally:
            os.unlink(result._session_path_tmp)

    def test_obfuscated_source_does_not_contain_original_strings(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        try:
            self.assertNotIn("Hello, ", result.source)
            self.assertNotIn("helioporbit-test-key-2024", result.source)
        finally:
            os.unlink(result._session_path_tmp)

    def test_obfuscated_source_does_not_contain_original_names(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        try:
            # Original function name should be renamed
            self.assertNotIn("def greet", result.source)
            self.assertNotIn("def add", result.source)
        finally:
            os.unlink(result._session_path_tmp)

    def test_session_is_encrypted(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        path   = result._session_path_tmp
        try:
            # Reading raw bytes should not yield readable JSON
            raw = Path(path).read_bytes()
            self.assertNotIn(b'"session_id"', raw)
            self.assertNotIn(b'"name_map"', raw)
        finally:
            os.unlink(path)

    def test_complex_source_obfuscates(self):
        result = self._obfuscate(COMPLEX_SOURCE)
        try:
            ast.parse(result.source)
        except SyntaxError as exc:
            self.fail(f"Complex source obfuscation failed: {exc}")
        finally:
            os.unlink(result._session_path_tmp)

    def test_source_inflation(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        try:
            # Obfuscated should be bigger
            self.assertGreater(len(result.source), len(SIMPLE_SOURCE))
        finally:
            os.unlink(result._session_path_tmp)

    def test_resistance_score_above_threshold(self):
        result = self._obfuscate(SIMPLE_SOURCE)
        try:
            analyser = Analyser()
            report   = analyser.analyse(
                SIMPLE_SOURCE, result.source,
                name_map=result.session.name_map,
                cff_map=result.session.cff_map,
            )
            self.assertGreaterEqual(report.resistance_score, 40)
        finally:
            os.unlink(result._session_path_tmp)


class TestDeobfuscationPipeline(unittest.TestCase):
    def _obf_deobf(self, src: str) -> str:
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            session_path = f.name
        try:
            obf    = Obfuscator()
            result = obf.obfuscate_source(src, PASSWORD, session_path=session_path)

            deobf   = Deobfuscator()
            restored = deobf.deobfuscate_source(result.source, session_path, PASSWORD)
            return restored
        finally:
            os.unlink(session_path)

    def test_strings_restored(self):
        src = 'x = "hello world"\ny = "secret string"\n'
        restored = self._obf_deobf(src)
        self.assertIn("hello world", restored)
        self.assertIn("secret string", restored)

    def test_integer_constants_restored(self):
        src = "a = 42\nb = 1000\nc = -99\n"
        restored = self._obf_deobf(src)
        code = compile(ast.parse(restored), "<r>", "exec")
        ns   = {}
        exec(code, ns)
        self.assertEqual(ns.get("a", None), 42)
        self.assertEqual(ns.get("b", None), 1000)
        self.assertEqual(ns.get("c", None), -99)

    def test_names_demangled(self):
        src = textwrap.dedent("""\
            def compute(value):
                result = value * 2
                return result
        """)
        restored = self._obf_deobf(src)
        self.assertIn("compute", restored)
        self.assertIn("value", restored)

    def test_deobf_wrong_password_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            session_path = f.name
        try:
            obf    = Obfuscator()
            result = obf.obfuscate_source(SIMPLE_SOURCE, PASSWORD, session_path=session_path)
            deobf  = Deobfuscator()
            with self.assertRaises(ValueError):
                deobf.deobfuscate_source(result.source, session_path, "wrong-password")
        finally:
            os.unlink(session_path)


# ──────────────────────────────────────────────────────────────────────────────
# Session tests
# ──────────────────────────────────────────────────────────────────────────────

class TestObfuscationSession(unittest.TestCase):
    def test_serialize_deserialize(self):
        s = ObfuscationSession()
        s.register_name("foo", "_h1234")
        s.register_string("_sXX", {"algo": "chacha", "ct_b85": "abc"})
        d = s.to_dict()
        s2 = ObfuscationSession.from_dict(d)
        self.assertEqual(s.session_id, s2.session_id)
        self.assertEqual(s.name_map, s2.name_map)

    def test_derive_subkey_different_purposes(self):
        s = ObfuscationSession()
        k1 = s.derive_subkey("strings")
        k2 = s.derive_subkey("names")
        self.assertNotEqual(k1, k2)

    def test_save_load_roundtrip(self):
        s = ObfuscationSession()
        s.register_name("hello", "_h_abc")
        with tempfile.NamedTemporaryFile(suffix=".hpb", delete=False) as f:
            path = f.name
        try:
            s.save_encrypted(path, "pw")
            s2 = ObfuscationSession.load_encrypted(path, "pw")
            self.assertEqual(s.session_id, s2.session_id)
            self.assertEqual(s.name_map,   s2.name_map)
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# File-based tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFileIO(unittest.TestCase):
    def test_obfuscate_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            src_path = Path(d) / "source.py"
            out_path = Path(d) / "output.hpo.py"
            ses_path = Path(d) / "session.hpb"
            src_path.write_text(SIMPLE_SOURCE)

            obf = Obfuscator()
            obf.obfuscate_file(str(src_path), PASSWORD,
                               str(out_path), str(ses_path))

            self.assertTrue(out_path.exists())
            self.assertTrue(ses_path.exists())

            # Obfuscated file should be valid Python
            ast.parse(out_path.read_text())

            # Deobfuscate
            deobf    = Deobfuscator()
            res_path = Path(d) / "restored.py"
            deobf.deobfuscate_file(str(out_path), str(ses_path), PASSWORD, str(res_path))
            self.assertTrue(res_path.exists())
            restored_src = res_path.read_text()
            self.assertIn("Hello", restored_src)


if __name__ == "__main__":
    unittest.main(verbosity=2)

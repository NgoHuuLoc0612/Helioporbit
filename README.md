# Helioporbit — Enterprise Python Obfuscator

```
  ██╗  ██╗███████╗██╗     ██╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██╗████████╗
  ██║  ██║██╔════╝██║     ██║██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝
  ███████║█████╗  ██║     ██║██║   ██║██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║
  ██╔══██║██╔══╝  ██║     ██║██║   ██║██╔═══╝ ██║   ██║██╔══██╗██╔══██╗██║   ██║
  ██║  ██║███████╗███████╗██║╚██████╔╝██║     ╚██████╔╝██║  ██║██████╔╝██║   ██║
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝
```

**Multi-layer, AST-level, cryptographically-anchored Python code protection.**

---

## Features

| Layer | Technique | Detail |
|---|---|---|
| **String encryption** | ChaCha20-Poly1305 / AES-128-CTR / XOR-multi | Per-string keys derived via HKDF; algorithm chosen randomly per literal |
| **Name mangling** | SHA-256 hash / Unicode confusables / Phonetic / Numeric | Scope-aware; preserves dunders, builtins, `__all__` exports |
| **Control flow flattening** | `while True` / `if _hpb_st == …` dispatcher | Block IDs XOR-obfuscated; order shuffled from session key |
| **Integer encoding** | XOR-split / Add-split / Double-negate / Nested XOR | Up to depth-3 recursive encoding |
| **Dead code injection** | Opaque predicates / if-False blocks / Fake loops | Predicates guaranteed always-True/False via number theory |
| **Anti-debug stubs** | `sys.gettrace()` / stack-frame inspection / env checks | Passive or aggressive modes |
| **Junk imports** | 8+ unused stdlib imports with mangled aliases | Noise for import analysis tools |
| **Lambda conversion** | Single-expression functions → lambda assignments | Adds cognitive load for reverse engineers |
| **Docstring stripping** | Module/class/function docstrings removed | Eliminates documentation-based analysis |
| **Body shuffling** | Top-level definition order randomised | Cross-reference analysis harder |
| **Session encryption** | PBKDF2-SHA512 (600k iter) + ChaCha20-Poly1305 | `.hpb` artefact required for deobfuscation |

---

## Quick Start

### Install

```bash
pip install -e .                     # editable install
pip install -e ".[fast]"             # + PyCryptodome for faster crypto
```

### Obfuscate

```bash
python -m helioporbit obfuscate mymodule.py -p "my-password"
# → mymodule.hpo.py   (obfuscated source)
# → mymodule.hpb      (encrypted session file — keep this safe!)
```

### Deobfuscate

```bash
python -m helioporbit deobfuscate mymodule.hpo.py -s mymodule.hpb -p "my-password"
# → mymodule.hpo.deobf.py
```

### Analyse

```bash
python -m helioporbit analyse mymodule.py mymodule.hpo.py
```

### Python API

```python
from helioporbit import Obfuscator, Deobfuscator
from helioporbit.core.session import TransformConfig

# Obfuscate
cfg = TransformConfig(
    string_encrypt_algo  = "chacha",      # chacha | aes_ctr | xor
    name_mangle_style    = "hash",        # hash | unicode | phonetic | numeric
    dead_code_ratio      = 0.35,          # 0.0 – 1.0
    integer_encode_depth = 3,             # recursion depth
    junk_import_count    = 8,
    anti_debug_mode      = "aggressive",  # passive | aggressive | none
)

obf    = Obfuscator(config=cfg)
result = obf.obfuscate_file("mymodule.py", session_password="secret",
                             output_path="mymodule.hpo.py",
                             session_path="mymodule.hpb")
print(result)  # ObfuscationResult(session_id=…, output_path=…)

# Deobfuscate
deobf   = Deobfuscator()
restored = deobf.deobfuscate_file("mymodule.hpo.py",
                                   session_path="mymodule.hpb",
                                   session_password="secret")
```

---

## CLI Reference

```
helioporbit obfuscate INPUT [options]
  -o, --output PATH         Output .py path (default: INPUT.hpo.py)
  -s, --session PATH        Session .hpb path (default: INPUT.hpb)
  -p, --password PASSWORD   Session password (prompted if omitted)
  --string-algo ALGO        chacha | aes_ctr | xor  (default: chacha)
  --name-style STYLE        hash | unicode | phonetic | numeric
  --name-prefix PREFIX      Mangled name prefix (default: _h)
  --dead-ratio RATIO        Dead code injection ratio 0.0–1.0 (default: 0.35)
  --int-depth N             Integer encoding depth (default: 3)
  --junk-imports N          Junk import count (default: 8)
  --anti-debug MODE         passive | aggressive | none
  --analyse                 Print analysis report after obfuscation
  -v, --verbose

helioporbit deobfuscate INPUT -s SESSION [options]
  -o, --output PATH         Output .py path
  -p, --password PASSWORD

helioporbit analyse ORIGINAL OBFUSCATED

helioporbit verify SESSION [-p PASSWORD]
```

---

## Architecture

```
helioporbit/
├── core/
│   ├── session.py          Session artefact — key material, name/string/CFF maps
│   ├── obfuscator.py       Pipeline orchestrator (11 transform steps)
│   └── deobfuscator.py     Reversal engine (7 phases + post-CFF cleanup)
├── crypto/
│   ├── primitives.py       ChaCha20, AES-CTR, XOR-multi, PBKDF2, HKDF, Poly1305
│   ├── string_encryptor.py Per-string key derivation + runtime bootstrap code
│   └── session_crypt.py    .hpb file format (PBKDF2 + ChaCha20-Poly1305)
├── transforms/
│   ├── name_mangler.py     Scope-aware identifier renaming (4 styles)
│   ├── control_flow_flattener.py  While-True dispatcher CFF
│   ├── integer_encoder.py  Constant arithmetic obfuscation
│   ├── dead_code_injector.py  Opaque predicates + junk statements
│   ├── string_transformer.py  AST visitor for string literal replacement
│   └── anti_debug.py       Anti-debug stubs, junk imports, lambda converter
├── analysis/
│   └── __init__.py         Shannon entropy, complexity, resistance score
├── cli/
│   └── __init__.py         argparse CLI (obfuscate/deobfuscate/analyse/verify)
└── tests/
    └── test_helioporbit.py  63 unit + integration tests
```

---

## Obfuscation Pipeline (ordered)

```
Source  →  1. Parse & annotation-strip
        →  2. Junk imports + anti-debug stubs
        →  3. String encryption (ChaCha20/AES/XOR per literal, HKDF per key)
        →  4. Bootstrap injection (_hpb_ds / _hpb_cc / _hpb_xd runtime)
        →  5. Integer constant encoding (recursive arithmetic obfuscation)
        →  6. Lambda conversion (single-expr functions → lambda)
        →  7. Name mangling (SHA-256 hash of master_key + identifier)
        →  8. Control flow flattening (while-True/if-elif dispatcher)
        →  9. Dead code injection (opaque predicates, fake loops, junk assigns)
        → 10. Top-level definition shuffling
        → 11. AST unparse → protected .py output
```

## Deobfuscation Pipeline (session required)

```
Protected source  →  1. String restoration (_hpb_ds → plaintext literals)
                 →  2. Integer folding (constant-fold arithmetic back to literals)
                 →  3. Junk / bootstrap / dead-code removal
                 →  4. CFF reversal (while-True → original linear sequence)
                 →  5. Post-CFF cleanup (_hpb_st/_hpb_rv scaffolding)
                 →  6. Name de-mangling (session reverse_name_map)
                 →  7. Builtin alias reversal
                 →  8. Import re-ordering
                 →  9. AST unparse → restored .py
```

---

## Session File (.hpb) Format

```
[4B magic "HPOB"] [1B version] [32B salt] [12B nonce] [16B Poly1305 tag] [N bytes ciphertext]
```

- Key derivation: **PBKDF2-SHA512**, 600,000 iterations
- Authenticated encryption: **ChaCha20-Poly1305**
- Session contains: master key, name map, string table, CFF map, config

**Without the `.hpb` file and correct password, deobfuscation is computationally infeasible.**

---

## Requirements

- Python ≥ 3.9 (uses `ast.unparse`)
- No mandatory dependencies (pure-Python fallback for all crypto)
- Optional: `pycryptodome` for hardware-accelerated AES/ChaCha20

---

## Test Suite

```bash
python -m pytest helioporbit/tests/test_helioporbit.py -v
# 63 passed
```

Covers: ChaCha20, AES-CTR, XOR-multi, Poly1305, PBKDF2, HKDF,
session encrypt/decrypt, string encryptor, name mangler (4 styles),
integer encoder, CFF, dead code injector, safe-eval, integer folder,
analysis metrics, full obfuscation pipeline, full deobfuscation pipeline,
semantic verification, file I/O roundtrip.

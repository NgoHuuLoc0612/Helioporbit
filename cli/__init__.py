"""
helioporbit.cli
Command-line interface for Helioporbit.

Commands:
  obfuscate   Obfuscate a Python source file
  deobfuscate Restore an obfuscated file using a session (.hpb)
  analyse     Report obfuscation quality metrics
  verify      Verify session integrity / password

Usage examples:
  python -m helioporbit obfuscate mymodule.py -p "secret" -o out.py
  python -m helioporbit deobfuscate out.py -s session.hpb -p "secret" -o restored.py
  python -m helioporbit analyse mymodule.py out.py
  python -m helioporbit verify session.hpb -p "secret"
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
import traceback
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _prompt_password(prompt: str = "Session password") -> str:
    try:
        return getpass.getpass(f"{prompt}: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)


def _require_file(path: str, label: str) -> Path:
    p = Path(path)
    if not p.exists():
        print("[error] " + label + " not found: " + str(path), file=sys.stderr)
        sys.exit(1)
    return p


def _banner() -> str:
    return (
        "\n"
        "  ██╗  ██╗███████╗██╗     ██╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██╗████████╗\n"
        "  ██║  ██║██╔════╝██║     ██║██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝\n"
        "  ███████║█████╗  ██║     ██║██║   ██║██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║   \n"
        "  ██╔══██║██╔══╝  ██║     ██║██║   ██║██╔═══╝ ██║   ██║██╔══██╗██╔══██╗██║   ██║   \n"
        "  ██║  ██║███████╗███████╗██║╚██████╔╝██║     ╚██████╔╝██║  ██║██████╔╝██║   ██║   \n"
        "  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝   \n"
        "  Enterprise Python Obfuscator  ·  v1.0.0\n"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Command: obfuscate
# ──────────────────────────────────────────────────────────────────────────────

def cmd_obfuscate(args: argparse.Namespace) -> int:
    from helioporbit.core.obfuscator import Obfuscator
    from helioporbit.core.session import TransformConfig

    src_path = _require_file(args.input, "Input file")
    password = args.password or _prompt_password("Session password")

    cfg = TransformConfig(
        string_encrypt_algo       = args.string_algo,
        name_mangle_style         = args.name_style,
        name_mangle_prefix        = args.name_prefix,
        cff_dispatch              = "while_switch",
        opaque_complexity         = args.opaque_complexity,
        dead_code_ratio           = args.dead_ratio,
        integer_encode_depth      = args.int_depth,
        junk_import_count         = args.junk_imports,
        anti_debug_mode           = args.anti_debug,
        wordlist_path             = getattr(args, "wordlist_path", ""),
        use_wordlist              = getattr(args, "use_wordlist", False),
        string_split_probability  = getattr(args, "split_prob", 0.70),
        junk_class_count          = getattr(args, "junk_classes", 3),
        junk_func_count           = getattr(args, "junk_funcs", 4),
        comment_pollution_density = getattr(args, "comment_density", 0.20),
        secret_fragment           = getattr(args, "secret_fragment", True),
        function_split            = getattr(args, "function_split", True),
        literal_encode            = getattr(args, "literal_encode", True),
        encrypt_bytecode          = getattr(args, "encrypt_bytecode", False),
    )

    out_path     = args.output or str(src_path.with_suffix(".hpo.py"))
    session_path = args.session or str(src_path.with_suffix(".hpb"))

    print("[*] Input          : " + str(src_path))
    print("[*] Output         : " + str(out_path))
    print("[*] Session file   : " + str(session_path))
    print("[*] Name style     : " + cfg.name_mangle_style + (" + wordlist" if cfg.use_wordlist else ""))
    print("[*] String algo    : " + cfg.string_encrypt_algo)
    print("[*] Anti-debug     : " + cfg.anti_debug_mode)
    print("[*] Dead code ratio: " + str(cfg.dead_code_ratio))
    print("[*] String split   : " + str(cfg.string_split_probability))
    print("[*] Junk classes   : " + str(cfg.junk_class_count))
    print("[*] Comment noise  : " + str(cfg.comment_pollution_density))
    if cfg.use_wordlist:
        wl_src = cfg.wordlist_path if cfg.wordlist_path else "built-in"
        print("[*] Wordlist       : " + wl_src)
    print("[*] Starting obfuscation pipeline...")

    t0 = time.perf_counter()
    try:
        obf = Obfuscator(config=cfg)
        result = obf.obfuscate_file(
            str(src_path),
            session_password=password,
            output_path=out_path,
            session_path=session_path,
        )
    except Exception as exc:
        print("[error] Obfuscation failed: " + str(exc), file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1

    elapsed = time.perf_counter() - t0

    if args.analyse:
        _print_analysis(src_path.read_text(), result.source, result.session)

    print("[OK] Done in " + str(round(elapsed, 2)) + "s")
    print("    Output  -> " + str(out_path))
    print("    Session -> " + str(session_path))
    print("Warning: Keep the session file (.hpb) safe -- required for deobfuscation.")
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Command: deobfuscate
# ──────────────────────────────────────────────────────────────────────────────

def cmd_deobfuscate(args: argparse.Namespace) -> int:
    from helioporbit.core.deobfuscator import Deobfuscator

    src_path     = _require_file(args.input, "Obfuscated file")
    session_path = _require_file(args.session, "Session file")
    password     = args.password or _prompt_password("Session password")

    out_path = args.output or str(src_path.with_suffix(".deobf.py"))

    print("[*] Input          : " + str(src_path))
    print("[*] Session file   : " + str(session_path))
    print("[*] Output         : " + str(out_path))
    print("[*] Decrypting session & reversing transforms…")

    t0 = time.perf_counter()
    try:
        deobf = Deobfuscator()
        result = deobf.deobfuscate_file(
            str(src_path),
            str(session_path),
            password,
            out_path,
        )
    except ValueError as exc:
        print("[error] " + str(exc), file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print("[error] Unexpected failure: " + str(exc), file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1

    elapsed = time.perf_counter() - t0
    print("[OK] Deobfuscation complete in " + str(round(elapsed, 2)) + "s")
    print("    Output -> " + str(out_path))
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Command: analyse
# ──────────────────────────────────────────────────────────────────────────────

def cmd_analyse(args: argparse.Namespace) -> int:
    from helioporbit.analysis import Analyser

    orig_path = _require_file(args.original, "Original source")
    obf_path  = _require_file(args.obfuscated, "Obfuscated source")

    orig_src = orig_path.read_text(encoding="utf-8")
    obf_src  = obf_path.read_text(encoding="utf-8")

    analyser = Analyser()
    report   = analyser.analyse(orig_src, obf_src)
    print(report.summary())
    return 0


def _print_analysis(orig_src: str, obf_src: str, session) -> None:
    from helioporbit.analysis import Analyser
    analyser = Analyser()
    report   = analyser.analyse(
        orig_src, obf_src,
        name_map=session.name_map,
        cff_map=session.cff_map,
    )
    print()
    print(report.summary())


# ──────────────────────────────────────────────────────────────────────────────
# Command: verify
# ──────────────────────────────────────────────────────────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    from helioporbit.core.session import ObfuscationSession

    session_path = _require_file(args.session, "Session file")
    password     = args.password or _prompt_password("Session password")

    print("[*] Verifying session: " + str(session_path))
    try:
        session = ObfuscationSession.load_encrypted(str(session_path), password)
    except ValueError as exc:
        print("[FAIL] Verification FAILED: " + str(exc), file=sys.stderr)
        return 1

    import time as _t
    created = _t.strftime("%Y-%m-%d %H:%M:%S UTC", _t.gmtime(session.created_at))
    print("[OK] Session verified successfully")
    print("    Session ID     : " + session.session_id)
    print("    Created        : " + created)
    print("    Version        : " + str(session.version))
    print("    Source hash    : " + session.source_hash)
    print("    Strings table  : " + str(len(session.string_table)) + " entries")
    print("    Name map       : " + str(len(session.name_map)) + " entries")
    print("    CFF map        : " + str(len(session.cff_map)) + " functions")
    print("    Transforms     : " + ", ".join(session.transform_order))
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="helioporbit",
        description="Enterprise Python Obfuscator & Deobfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="Helioporbit 1.0.0")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── obfuscate ──────────────────────────────────────────────────────────────
    p_obf = sub.add_parser("obfuscate", help="Obfuscate a Python source file",
                            aliases=["obf", "o"])
    p_obf.add_argument("input",  metavar="INPUT",  help="Source .py file")
    p_obf.add_argument("-o", "--output",  metavar="OUTPUT", help="Output path (default: <input>.hpo.py)")
    p_obf.add_argument("-s", "--session", metavar="SESSION", help="Session file path (default: <input>.hpb)")
    p_obf.add_argument("-p", "--password", metavar="PASSWORD", help="Session encryption password")
    p_obf.add_argument("--string-algo",  choices=["chacha", "aes_ctr", "xor"],
                        default="chacha", dest="string_algo",
                        help="String encryption algorithm (default: chacha)")
    p_obf.add_argument("--name-style",   choices=["hash", "unicode", "phonetic", "numeric"],
                        default="hash", dest="name_style",
                        help="Name mangling style (default: hash)")
    p_obf.add_argument("--name-prefix",  default="_h", dest="name_prefix",
                        help="Name mangling prefix (default: _h)")
    p_obf.add_argument("--opaque-complexity", type=int, default=4,
                        dest="opaque_complexity", metavar="N",
                        help="Opaque predicate complexity 1-10 (default: 4)")
    p_obf.add_argument("--dead-ratio",   type=float, default=0.35,
                        dest="dead_ratio", metavar="RATIO",
                        help="Dead code injection ratio 0.0–1.0 (default: 0.35)")
    p_obf.add_argument("--int-depth",    type=int, default=3,
                        dest="int_depth", metavar="DEPTH",
                        help="Integer encoding recursion depth (default: 3)")
    p_obf.add_argument("--junk-imports", type=int, default=8,
                        dest="junk_imports", metavar="N",
                        help="Number of junk imports to inject (default: 8)")
    p_obf.add_argument("--anti-debug",  choices=["passive", "aggressive", "none"],
                        default="aggressive", dest="anti_debug",
                        help="Anti-debug mode (default: aggressive)")
    p_obf.add_argument("--wordlist",    metavar="FILE", default="",
                        dest="wordlist_path",
                        help="Path to wordlist file for name mangling (one word per line)")
    p_obf.add_argument("--use-wordlist", action="store_true", dest="use_wordlist",
                        help="Enable wordlist-based name mangling (auto-detects wordlist.txt in transforms/)")
    p_obf.add_argument("--no-secret-fragment", action="store_false", dest="secret_fragment",
                        help="Disable secret string fragmentation")
    p_obf.add_argument("--no-func-split", action="store_false", dest="function_split",
                        help="Disable function splitting")
    p_obf.add_argument("--no-literal-encode", action="store_false", dest="literal_encode",
                        help="Disable bool/None/bytes/float literal encoding")
    p_obf.add_argument("--encrypt-bytecode", action="store_true", dest="encrypt_bytecode",
                        help="Add encrypted bytecode layer (requires C extension: python setup_loader.py build_ext --inplace)")
    p_obf.add_argument("--split-prob",  type=float, default=0.70,
                        dest="split_prob", metavar="PROB",
                        help="String split/encode probability 0.0-1.0 (default: 0.70)")
    p_obf.add_argument("--junk-classes", type=int, default=3,
                        dest="junk_classes", metavar="N",
                        help="Number of junk classes to inject (default: 3)")
    p_obf.add_argument("--junk-funcs",   type=int, default=4,
                        dest="junk_funcs", metavar="N",
                        help="Number of junk functions to inject (default: 4)")
    p_obf.add_argument("--comment-density", type=float, default=0.20,
                        dest="comment_density", metavar="DENSITY",
                        help="Misleading comment injection density 0.0-1.0 (default: 0.20)")
    p_obf.add_argument("--analyse", action="store_true",
                        help="Print analysis report after obfuscation")
    p_obf.add_argument("-v", "--verbose", action="store_true")

    # ── deobfuscate ────────────────────────────────────────────────────────────
    p_deobf = sub.add_parser("deobfuscate", help="Restore an obfuscated file",
                              aliases=["deobf", "d"])
    p_deobf.add_argument("input",   metavar="INPUT",   help="Obfuscated .hpo.py file")
    p_deobf.add_argument("-s", "--session", metavar="SESSION", required=True,
                          help="Session .hpb file")
    p_deobf.add_argument("-o", "--output",  metavar="OUTPUT",
                          help="Output path (default: <input>.deobf.py)")
    p_deobf.add_argument("-p", "--password", metavar="PASSWORD",
                          help="Session encryption password")
    p_deobf.add_argument("-v", "--verbose", action="store_true")

    # ── analyse ────────────────────────────────────────────────────────────────
    p_an = sub.add_parser("analyse", help="Analyse obfuscation quality",
                           aliases=["analyze", "a"])
    p_an.add_argument("original",   metavar="ORIGINAL",   help="Original .py file")
    p_an.add_argument("obfuscated", metavar="OBFUSCATED", help="Obfuscated .py file")

    # ── verify ─────────────────────────────────────────────────────────────────
    p_ver = sub.add_parser("verify", help="Verify session file integrity",
                            aliases=["v"])
    p_ver.add_argument("session", metavar="SESSION", help="Session .hpb file")
    p_ver.add_argument("-p", "--password", metavar="PASSWORD",
                       help="Session encryption password")

    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    print(_banner())
    parser = build_parser()
    args   = parser.parse_args(argv)

    cmd = args.command
    if cmd in ("obfuscate", "obf", "o"):
        return cmd_obfuscate(args)
    elif cmd in ("deobfuscate", "deobf", "d"):
        return cmd_deobfuscate(args)
    elif cmd in ("analyse", "analyze", "a"):
        return cmd_analyse(args)
    elif cmd in ("verify", "v"):
        return cmd_verify(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
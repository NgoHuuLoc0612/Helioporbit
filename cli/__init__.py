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
        print(f"[error] {label} not found: {path}", file=sys.stderr)
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
        string_encrypt_algo  = args.string_algo,
        name_mangle_style    = args.name_style,
        name_mangle_prefix   = args.name_prefix,
        cff_dispatch         = "while_switch",
        opaque_complexity    = args.opaque_complexity,
        dead_code_ratio      = args.dead_ratio,
        integer_encode_depth = args.int_depth,
        junk_import_count    = args.junk_imports,
        anti_debug_mode      = args.anti_debug,
    )

    out_path     = args.output or str(src_path.with_suffix(".hpo.py"))
    session_path = args.session or str(src_path.with_suffix(".hpb"))

    print(f"[*] Input          : {src_path}")
    print(f"[*] Output         : {out_path}")
    print(f"[*] Session file   : {session_path}")
    print(f"[*] Name style     : {cfg.name_mangle_style}")
    print(f"[*] String algo    : {cfg.string_encrypt_algo}")
    print(f"[*] Anti-debug     : {cfg.anti_debug_mode}")
    print(f"[*] Dead code ratio: {cfg.dead_code_ratio}")
    print("[*] Starting obfuscation pipeline…")

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
        print(f"[error] Obfuscation failed: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1

    elapsed = time.perf_counter() - t0

    if args.analyse:
        _print_analysis(src_path.read_text(), result.source, result.session)

    print(f"\n[✓] Done in {elapsed:.2f}s")
    print(f"    Output  → {out_path}")
    print(f"    Session → {session_path}")
    print(f"\n  ⚠ Keep the session file (.hpb) safe — it is required for deobfuscation.")
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

    print(f"[*] Input          : {src_path}")
    print(f"[*] Session file   : {session_path}")
    print(f"[*] Output         : {out_path}")
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
        print(f"[error] {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1
    except Exception as exc:
        print(f"[error] Unexpected failure: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return 1

    elapsed = time.perf_counter() - t0
    print(f"\n[✓] Deobfuscation complete in {elapsed:.2f}s")
    print(f"    Output → {out_path}")
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

    print(f"[*] Verifying session: {session_path}")
    try:
        session = ObfuscationSession.load_encrypted(str(session_path), password)
    except ValueError as exc:
        print(f"[✗] Verification FAILED: {exc}", file=sys.stderr)
        return 1

    import time as _t
    created = _t.strftime("%Y-%m-%d %H:%M:%S UTC", _t.gmtime(session.created_at))
    print(f"[✓] Session verified successfully")
    print(f"    Session ID     : {session.session_id}")
    print(f"    Created        : {created}")
    print(f"    Version        : {session.version}")
    print(f"    Source hash    : {session.source_hash}")
    print(f"    Strings table  : {len(session.string_table)} entries")
    print(f"    Name map       : {len(session.name_map)} entries")
    print(f"    CFF map        : {len(session.cff_map)} functions")
    print(f"    Transforms     : {', '.join(session.transform_order)}")
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

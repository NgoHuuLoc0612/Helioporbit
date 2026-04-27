"""
helioporbit.crypto.string_encryptor
Encrypts string literals found in AST nodes and injects runtime-decryption
stubs that are different for each occurrence.

Three encryption algorithms are supported, chosen randomly per string:
  1. chacha  — ChaCha20-Poly1305
  2. aes_ctr — AES-128-CTR
  3. xor     — multi-round XOR with SHAKE-256 derived streams

The runtime bootstrap snippet is injected once at the top of the module.
Each encrypted string becomes a call to a unique per-string lambda that
decrypts on first access and caches the result.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import os
import random
import secrets
import textwrap
from typing import Dict, List, Tuple

from helioporbit.crypto.primitives import (
    chacha20_poly1305_encrypt,
    aes_ctr_encrypt,
    xor_multi_encrypt,
    hkdf,
    secure_random_bytes,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.b85encode(data).decode()


def _derive_per_string_key(master_key: bytes, string_id: str, length: int = 32) -> bytes:
    return hkdf(master_key, b"str:" + string_id.encode(), b"string-key", length)


# ──────────────────────────────────────────────────────────────────────────────
# Bootstrap code (injected once per module)
# ──────────────────────────────────────────────────────────────────────────────

BOOTSTRAP_TEMPLATE = '''
import base64 as _b85mod, hashlib as _hmod, struct as _stmod, hmac as _hmmod
def _hpb_cc(k,n,d):
    _P=(1<<130)-5
    def _qr(a,b,c,d):
        a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>(16)))&0xFFFFFFFF
        c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>(20)))&0xFFFFFFFF
        a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>(24)))&0xFFFFFFFF
        c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>(25)))&0xFFFFFFFF
        return a,b,c,d
    def _blk(k,ctr,n):
        import struct as _s
        C=[0x61707865,0x3320646E,0x79622D32,0x6B206574]
        kw=list(_s.unpack_from('<8I',k));nw=list(_s.unpack_from('<3I',n))
        st=C+kw+[ctr]+nw;w=list(st)
        for _ in range(10):
            w[0],w[4],w[8],w[12]=_qr(w[0],w[4],w[8],w[12])
            w[1],w[5],w[9],w[13]=_qr(w[1],w[5],w[9],w[13])
            w[2],w[6],w[10],w[14]=_qr(w[2],w[6],w[10],w[14])
            w[3],w[7],w[11],w[15]=_qr(w[3],w[7],w[11],w[15])
            w[0],w[5],w[10],w[15]=_qr(w[0],w[5],w[10],w[15])
            w[1],w[6],w[11],w[12]=_qr(w[1],w[6],w[11],w[12])
            w[2],w[7],w[8],w[13]=_qr(w[2],w[7],w[8],w[13])
            w[3],w[4],w[9],w[14]=_qr(w[3],w[4],w[9],w[14])
        return _s.pack('<16I',*[(w[i]+st[i])&0xFFFFFFFF for i in range(16)])
    out=bytearray()
    for i,s in enumerate(range(0,len(d),64)):
        ks=_blk(k,1+i,n);bl=d[s:s+64];out+=bytes(a^b for a,b in zip(bl,ks))
    return bytes(out)
def _hpb_xd(k,d):
    buf=bytearray(d)
    for r in range(3):
        rk=_hmod.sha512(k+r.to_bytes(4,'little')+b'xor_round').digest()
        st=_hmod.shake_256(rk).digest(len(buf))
        buf=bytearray(a^b for a,b in zip(buf,st))
    return bytes(buf)
def _hpb_aes(k,n,d):
    try:
        from Crypto.Cipher import AES;from Crypto.Util import Counter
        return AES.new(k,AES.MODE_CTR,counter=Counter.new(128,initial_value=int.from_bytes(n,'big'))).decrypt(d)
    except ImportError:
        return _hpb_cc(k.ljust(32,b'\\x00')[:32],n[:12],d)
_hpb_cache={}
def _hpb_ds(sid,algo,ct,k,n,tag=None):
    if sid in _hpb_cache:return _hpb_cache[sid]
    ct=_b85mod.b85decode(ct);k=_b85mod.b85decode(k);n=_b85mod.b85decode(n)
    if algo==0:r=_hpb_cc(k,n,ct)
    elif algo==1:r=_hpb_aes(k,n,ct)
    else:r=_hpb_xd(k,ct)
    _hpb_cache[sid]=r.decode('utf-8','replace');return _hpb_cache[sid]
'''

ALGO_MAP = {"chacha": 0, "aes_ctr": 1, "xor": 2}


# ──────────────────────────────────────────────────────────────────────────────
# Main encryptor
# ──────────────────────────────────────────────────────────────────────────────

class StringEncryptor:
    def __init__(self, master_key: bytes, algo: str = "chacha", rng: random.Random = None):
        self.master_key = master_key
        self.algo       = algo
        self.rng        = rng or random.Random(int.from_bytes(master_key[:8], "little"))
        self._counter   = 0
        self.metadata: Dict[str, dict] = {}  # sid -> {algo, ct_b64, key_b64, nonce_b64}

    def _next_sid(self) -> str:
        self._counter += 1
        raw = hashlib.sha256(
            self.master_key + self._counter.to_bytes(8, "little")
        ).digest()[:12]
        return "_s" + raw.hex()

    def encrypt_string(self, s: str) -> Tuple[str, dict]:
        """
        Returns (sid, meta) where sid is the unique placeholder identifier.
        meta contains everything needed to decrypt at runtime and for the session.
        """
        sid     = self._next_sid()
        raw     = s.encode("utf-8")
        key     = _derive_per_string_key(self.master_key, sid)
        nonce   = secure_random_bytes(12)

        # Randomly vary algorithm per string for extra confusion
        chosen_algo = self.rng.choice(["chacha", "aes_ctr", "xor"])

        if chosen_algo == "chacha":
            ct, tag = chacha20_poly1305_encrypt(key, nonce, raw)
        elif chosen_algo == "aes_ctr":
            ct  = aes_ctr_encrypt(key[:16], nonce[:16].ljust(16, b"\x00"), raw)
            tag = None
        else:
            ct  = xor_multi_encrypt(key, raw)
            tag = None

        meta = {
            "algo":     chosen_algo,
            "algo_id":  ALGO_MAP[chosen_algo],
            "ct_b85":   _b64(ct),
            "key_b85":  _b64(key),
            "nonce_b85": _b64(nonce),
            "original": s,
        }
        self.metadata[sid] = meta
        return sid, meta

    def make_call_node(self, sid: str, meta: dict) -> ast.Call:
        """
        Build an AST node that calls _hpb_ds(sid, algo_id, ct, key, nonce).
        """
        return ast.Call(
            func=ast.Name(id="_hpb_ds", ctx=ast.Load()),
            args=[
                ast.Constant(value=sid),
                ast.Constant(value=meta["algo_id"]),
                ast.Constant(value=meta["ct_b85"]),
                ast.Constant(value=meta["key_b85"]),
                ast.Constant(value=meta["nonce_b85"]),
            ],
            keywords=[],
        )

    @staticmethod
    def bootstrap_ast_nodes() -> List[ast.stmt]:
        """Parse BOOTSTRAP_TEMPLATE into AST statement nodes."""
        tree = ast.parse(textwrap.dedent(BOOTSTRAP_TEMPLATE))
        return tree.body

"""Audited LAS-SG reference implementation.

This implementation uses the corrected algebraic interpretation of the paper:
SMpr = (Mk + sigma)^-1 P, so (Mk + sigma) * BSM reconstructs ASM.
It is a research prototype, not a production grid-control component.
"""
from __future__ import annotations

import base64, hashlib, hmac, json, secrets, time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac as chmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()
P = ec.derive_private_key(1, CURVE).public_key()


def _b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _unb64(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def _canon(*parts: Any) -> bytes:
    return b"|".join(str(x).encode() if not isinstance(x, bytes) else x for x in parts)
def _hash(*parts: Any) -> bytes:
    return hashlib.sha256(_canon(*parts)).digest()
def _int_bytes(n: int) -> bytes: return n.to_bytes(32, "big")
def _priv_from_scalar(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, CURVE)
def _pub_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(ec.Encoding.X962, ec.PublicFormat.CompressedPoint)
def _load_pub(b: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)
def _point_add(a: ec.EllipticCurvePublicKey, b: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    # cryptography does not expose point addition; derive the needed group relation
    # via ECDH-compatible scalar construction in the protocol instead. This helper
    # remains intentionally unused and documents the unsupported operation.
    raise NotImplementedError


def _scalar_mul_point(scalar: int, point: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    # Use public-key arithmetic through the library's supported ECDH operation is
    # not possible for arbitrary point output. The protocol stores point values as
    # scalar-backed objects internally and serializes public points at the boundary.
    raise NotImplementedError


@dataclass(frozen=True)
class Point:
    """Small prime-field ECC point implementation for protocol arithmetic.

    The implementation is intentionally isolated and tested; production systems
    should replace it with a vetted point-arithmetic library.
    """
    x: int
    y: int
    inf: bool = False

    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    A = (P - 3) % P
    B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    @classmethod
    def generator(cls): return cls(cls.GX, cls.GY)
    @classmethod
    def infinity(cls): return cls(0, 0, True)
    def encode(self) -> bytes:
        if self.inf: return b"\x00"
        return bytes([2 + (self.y & 1)]) + self.x.to_bytes(32, "big")
    @classmethod
    def decode(cls, b: bytes):
        if b == b"\x00": return cls.infinity()
        if len(b) != 33 or b[0] not in (2, 3): raise ValueError("invalid point encoding")
        x = int.from_bytes(b[1:], "big")
        if x >= cls.P: raise ValueError("invalid point")
        y2 = (pow(x, 3, cls.P) + cls.A*x + cls.B) % cls.P
        y = pow(y2, (cls.P + 1)//4, cls.P)
        if (y*y) % cls.P != y2: raise ValueError("point not on curve")
        if (y & 1) != (b[0] & 1): y = cls.P - y
        return cls(x, y)
    def __add__(self, q):
        if self.inf: return q
        if q.inf: return self
        if self.x == q.x and (self.y != q.y or self.y == 0): return Point.infinity()
        if self == q: m = ((3*self.x*self.x + self.A) * pow(2*self.y, -1, self.P)) % self.P
        else: m = ((q.y-self.y) * pow(q.x-self.x, -1, self.P)) % self.P
        x3 = (m*m-self.x-q.x) % self.P
        return Point(x3, (m*(self.x-x3)-self.y) % self.P)
    def __rmul__(self, k):
        k %= self.N
        r, a = Point.infinity(), self
        while k:
            if k & 1: r = r + a
            a, k = a + a, k >> 1
        return r


def _key(label: str, *parts: Any) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()).derive(_hash(*parts))

def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

def _aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 28: raise ValueError("invalid ciphertext")
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)

@dataclass
class Registration:
    smid: str
    sigma: int
    smpr: int
    st: bytes
    idst: str
    pseudonym: bytes

class NANGateway:
    def __init__(self, master_secret: int | None = None, clock=time.time):
        self.mk = master_secret or secrets.randbelow(Point.N - 1) + 1
        self.clock = clock
        self.registry: dict[str, Registration] = {}
    @property
    def public_key(self): return self.mk * Point.generator()
    def register(self, smid: str) -> Registration:
        if smid in self.registry: raise ValueError("meter already registered")
        sigma = int.from_bytes(_hash("sigma", smid), "big") % Point.N
        if sigma == 0: sigma = 1
        smpr = pow((self.mk + sigma) % Point.N, -1, Point.N)
        st = _hash("token", smid, self.mk, smpr)
        idst = _b64(secrets.token_bytes(12))
        reg = Registration(smid, sigma, smpr, st, idst, _aead_encrypt(_key("pid", self.mk), _canon(idst)))
        self.registry[smid] = reg
        return reg
    def authenticate(self, msg1: dict, now: float | None = None) -> tuple[dict, bytes]:
        now = self.clock() if now is None else now
        if abs(now - msg1["t1"]) > msg1.get("window", 30): raise ValueError("stale message 1")
        reg = next((r for r in self.registry.values() if hmac.compare_digest(r.pseudonym, _unb64(msg1["pid"]))), None)
        if reg is None: raise ValueError("unknown pseudonym")
        asm = Point.decode(_unb64(msg1["asm"]))
        bsm = Point.decode(_unb64(msg1["bsm"]))
        expected_l1 = _hash("l1", reg.smid, asm.encode(), bsm.encode(), msg1["t1"])
        expected_y1 = hmac.new(_key("mac", expected_l1), _canon(reg.smid, msg1["t1"], asm.encode(), reg.st), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_y1, _unb64(msg1["y1"])): raise ValueError("invalid message 1 MAC")
        # (Mk + sigma) * BSM = uP = ASM
        if ((self.mk + reg.sigma) % Point.N) * bsm != asm: raise ValueError("invalid message 1 algebra")
        v = secrets.randbelow(Point.N - 1) + 1
        cn = v * Point.generator()
        st_scalar = int.from_bytes(reg.st, "big") % Point.N or 1
        fn = ((v * st_scalar) % Point.N) * asm
        t2 = now
        y2 = hmac.new(_key("mac", expected_l1), _canon(asm.encode(), t2, cn.encode(), fn.encode()), hashlib.sha256).digest()
        sk = _hash("session", reg.smid, reg.st, asm.encode(), cn.encode(), fn.encode())
        new_id = _b64(secrets.token_bytes(12))
        q2 = _aead_encrypt(_key("state", sk), _canon(new_id, t2))
        return {"cn": _b64(cn.encode()), "fn": _b64(fn.encode()), "y2": _b64(y2), "q2": _b64(q2), "t2": t2, "window": msg1.get("window", 30)}, sk

class SmartMeter:
    def __init__(self, registration: Registration, clock=time.time):
        self.registration, self.clock = registration, clock
    @property
    def smid(self): return self.registration.smid
    def message1(self, now: float | None = None) -> dict:
        now = self.clock() if now is None else now
        u = secrets.randbelow(Point.N - 1) + 1
        asm, bsm = u * Point.generator(), u * (self.registration.smpr * Point.generator())
        l1 = _hash("l1", self.smid, asm.encode(), bsm.encode(), now)
        y1 = hmac.new(_key("mac", l1), _canon(self.smid, now, asm.encode(), self.registration.st), hashlib.sha256).digest()
        return {"pid": _b64(self.registration.pseudonym), "asm": _b64(asm.encode()), "bsm": _b64(bsm.encode()), "y1": _b64(y1), "t1": now, "window": 30, "_u": u, "_l1": l1}
    def finish(self, msg1: dict, msg2: dict, now: float | None = None) -> bytes:
        now = self.clock() if now is None else now
        if abs(now - msg2["t2"]) > msg2.get("window", 30): raise ValueError("stale message 2")
        asm = Point.decode(_unb64(msg1["asm"])); cn = Point.decode(_unb64(msg2["cn"]))
        fn = Point.decode(_unb64(msg2["fn"]))
        st_scalar = int.from_bytes(self.registration.st, "big") % Point.N or 1
        expected_fn = ((msg1["_u"] * st_scalar) % Point.N) * cn
        if fn != expected_fn: raise ValueError("invalid message 2 shared value")
        expected = hmac.new(_key("mac", msg1["_l1"]), _canon(asm.encode(), msg2["t2"], cn.encode(), fn.encode()), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(msg2["y2"])): raise ValueError("invalid message 2 MAC")
        return _hash("session", self.smid, self.registration.st, asm.encode(), cn.encode(), fn.encode())

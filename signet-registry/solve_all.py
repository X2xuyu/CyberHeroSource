#!/usr/bin/env python3
"""
Signet Registry - full solve.

Vulnerability: the /sign endpoint draws ECDSA nonces from a tiny pool
(period 8), so two different messages are signed with the SAME nonce k.
That leaks the private key. We then forge the "capability" signature,
which makes the registry hand back stage 1 plus an ECDH-sealed blob.
The blob is decrypted with the recovered private key (ChaCha-free, plain
ECDH -> sha256 -> AES-GCM), yielding stage 2. The flag is
CYBERHEROCTF{signet_<seg1><seg2>}.

Requires: pycryptodome (pip install pycryptodome)
"""
import json
import hashlib
import base64
import urllib.request

BASE = "http://192.168.30.134:8001"

# ---- secp256k1 ----------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def inv(a, m):
    return pow(a, -1, m)

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def point_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r

def h_msg(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N

# ---- HTTP helpers -------------------------------------------------------
def get(path):
    return json.loads(urllib.request.urlopen(BASE + path).read().decode())

def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()}

def b64d(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))

def sign(msg, d, k):
    z = h_msg(msg)
    R = point_mul(k, G)
    r = R[0] % N
    s = inv(k, N) * (z + d * r) % N
    return r, s

# ---- 1. nonce reuse -> private key -------------------------------------
def recover_key():
    sigs = []
    for i in range(20):
        m = "probe-%d" % i
        res = post("/sign", {"message": m})
        res["message"] = m
        sigs.append(res)
    seen = {}
    pair = None
    for s in sigs:
        if s["r"] in seen and seen[s["r"]]["message"] != s["message"]:
            pair = (seen[s["r"]], s)
            break
        seen[s["r"]] = s
    a, b = pair
    r  = int(a["r"], 16)
    s1 = int(a["s"], 16); s2 = int(b["s"], 16)
    z1 = h_msg(a["message"]); z2 = h_msg(b["message"])
    k = (z1 - z2) * inv((s1 - s2) % N, N) % N
    d = (s1 * k - z1) * inv(r, N) % N
    return d, (int(a["r"], 16) == int(b["r"], 16))

# ---- main ---------------------------------------------------------------
params = get("/params")
pub = (int(params["public_key"]["x"], 16), int(params["public_key"]["y"], 16))
d, reused = recover_key()
assert reused and point_mul(d, G) == pub, "key recovery failed"
print("[+] private key:", hex(d))

cap = params["capability_message"]
r, s = sign(cap, d, 0xC0FFEE1234567890ABCDEF)
resp = post("/capability", {"message": cap, "r": hex(r), "s": hex(s)})
seg1 = resp["segment"]
print("[+] stage 1 segment:", seg1)

eph = (int(resp["eph_public"]["x"], 16), int(resp["eph_public"]["y"], 16))
shared = point_mul(d, eph)
key = hashlib.sha256(shared[0].to_bytes(32, "big")).digest()
pt = AES_GCM_decrypt = None
try:
    from Crypto.Cipher import AES
    pt = AES.new(key, AES.MODE_GCM, nonce=b64d(resp["sealed_nonce"])).decrypt(
        b64d(resp["sealed_b64"]))
except ImportError:
    raise SystemExit("pip install pycryptodome")

# strip AES-GCM tag bytes after the JSON object
text = pt.decode("latin-1")
stage2 = json.loads(text[:text.rindex("}") + 1])
seg2 = stage2["segment"]
print("[+] stage 2 segment:", seg2)

flag = "CYBERHEROCTF{signet_%s%s}" % (seg1, seg2)
print("[+] FLAG:", flag)


#!/usr/bin/env python3
"""
Faultline Ledger - complete solve
1. RSA CRT fault attack  -> factor modulus, recover private key
2. RSA-OAEP(SHA-256)      -> decrypt sealed manifest (stage 1)
3. SHA-256 length ext.    -> forge ledger token, read sealed archive (stage 2)
4. AES-CTR nonce reuse    -> recover keystream, decrypt archive record (stage 3)
5. Assemble segments      -> flag
"""
import base64, math, json, requests
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from lengthext import extend

BASE = "http://192.168.30.135:8000"

def b64d(s):
    s = s.encode() if isinstance(s, str) else s
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# ---- 1. RSA fault attack -------------------------------------------------
pub = requests.get(BASE + "/public", timeout=10).json()
key = RSA.import_key(pub["public_key_pem"])
n, e = key.n, key.e
sealed = pub["sealed_manifest"]

msg = "faultline"
sigs = []
for _ in range(300):
    s = requests.post(BASE + "/sign", json={"message": msg}, timeout=10).json()["signature"]
    if s not in sigs:
        sigs.append(s)
    if len(sigs) >= 2:
        break
assert len(sigs) >= 2, "no faulty signature observed"

raw = [bytes_to_long(b64d(s)) for s in sigs]
p = None
for i in range(len(raw)):
    for j in range(i + 1, len(raw)):
        g = math.gcd(abs(raw[i] - raw[j]), n)
        if 1 < g < n:
            p = g
            break
    if p:
        break
assert p, "factorisation failed"
q = n // p
assert p * q == n
d = inverse(e, (p - 1) * (q - 1))
priv = RSA.construct((n, e, d, p, q))

# ---- 2. decrypt sealed manifest -----------------------------------------
stage1 = json.loads(PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(b64d(sealed)))
print("[stage1]", stage1)

# ---- 3. length-extension on ledger token --------------------------------
base_path = stage1["path"].encode()
token = stage1["token"]
secret_len = stage1["secret_len"]

def ledger(suffix: bytes):
    glue, dig = extend(token, secret_len + len(base_path), suffix)
    body = {"path_b64": b64e(base_path + glue + suffix), "token": dig}
    return requests.post(BASE + "/ledger", json=body, timeout=10).json()

stage2 = ledger(b"/sealed-archive")
print("[stage2]", stage2)

# ---- 4. AES-CTR nonce reuse -> keystream --------------------------------
note = "\u0000" * 192
ks = b64d(requests.post(BASE + "/archive", json={"note": note}, timeout=10).json()["ciphertext"])
ct = b64d(stage2["archive_record"])
plain = bytes(a ^ b for a, b in zip(ct, ks))
stage3 = json.loads(plain)
print("[stage3]", stage3)

# ---- 5. assemble --------------------------------------------------------
segments = [stage1["segment"], stage2["segment"], stage3["segment"]]
assembled = "".join(segments)
flag = "CYBERHEROCTF{faultline_" + assembled + "}"
print("[*] segments:", segments)
print("[FLAG]", flag)


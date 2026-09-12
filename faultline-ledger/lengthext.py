#!/usr/bin/env python3
"""SHA-256 length extension (hashpump equivalent), pure Python."""
import struct

K = [
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        S1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
        ch = (e & f) ^ ((~e & 0xffffffff) & g)
        t1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
        S0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xffffffff
        h=g; g=f; f=e; e=(d+t1)&0xffffffff
        d=c; c=b; b=a; a=(t1+t2)&0xffffffff
    return [(x+y)&0xffffffff for x,y in zip(state,[a,b,c,d,e,f,g,h])]

def sha256_glue(msg_len_bytes):
    """Padding bytes for a message of given length."""
    ml = msg_len_bytes
    glue = b'\x80'
    while (ml + len(glue)) % 64 != 56:
        glue += b'\x00'
    glue += struct.pack(">Q", ml * 8)
    return glue

class Sha256Ext:
    def __init__(self, digest: bytes, total_len: int):
        self.state = list(struct.unpack(">8I", digest))
        self.total = total_len  # bytes already hashed (secret||orig||glue)

    def update(self, data: bytes) -> bytes:
        state = self.state
        total = self.total
        # process data in 64-byte blocks; keep remainder implicitly by buffering
        buf = getattr(self, "buf", b"") + data
        full = (len(buf) // 64) * 64
        for off in range(0, full, 64):
            state = _compress(state, buf[off:off+64])
        self.buf = buf[full:]
        self.total = total + full
        self.state = state
        return self

    def hexdigest(self) -> str:
        # finalize with padding
        state = self.state
        total = self.total
        buf = getattr(self, "buf", b"")
        ml = total + len(buf)
        pad = sha256_glue(ml)
        buf2 = buf + pad
        for off in range(0, len(buf2), 64):
            state = _compress(state, buf2[off:off+64])
        return b"".join(struct.pack(">I", x) for x in state).hex()

def extend(digest_hex, orig_len, append: bytes):
    # digest already includes secret: total hashed = orig_len + len(glue)
    glue = sha256_glue(orig_len)
    ext = Sha256Ext(bytes.fromhex(digest_hex), orig_len + len(glue))
    ext.update(append)
    return glue, ext.hexdigest()

if __name__ == "__main__":
    # self-test: SHA256("abc")
    import hashlib
    class H:
        pass
    # simulate secret||msg hashing then extend
    secret = b"x" * 32
    msg = b"/ledger/public-notice"
    base = hashlib.sha256(secret + msg).hexdigest()
    glue, newdig = extend(base, len(secret) + len(msg), b"suffix")
    real = hashlib.sha256(secret + msg + glue + b"suffix").hexdigest()
    print("self-test:", newdig == real, glue.hex())


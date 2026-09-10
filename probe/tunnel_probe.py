#!/usr/bin/env python3
"""One-shot probe: establish Array /vpntunnel with existing ANsession cookie,
run the conf50/conf54 JSON negotiation, dump everything, then close."""
import socket, ssl, sys, uuid, time

HOST = "arrayvpn.pku.edu.cn"
COOKIE = open("/tmp/av_cookie_str.txt").read().strip()

conf50 = bytes([0x50,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0])
conf54 = bytes([0x54,0,0,0, 0,0,0,0, 0,0,0,0, 0x20,0,0,0,
                0x01,0,0,0, 0x0a,0,0x02,0x0f,0,
                0,0,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
                0x52,0x54,0,0xde, 0xa2,0xa6,0,0])

def read_response_head(ss):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = ss.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode(errors="replace"), rest

def read_some(ss, timeout=8):
    ss.settimeout(timeout)
    try:
        return ss.recv(65536)
    except socket.timeout:
        return b"<TIMEOUT>"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

raw = socket.create_connection((HOST, 443), timeout=15)
ss = ctx.wrap_socket(raw, server_hostname=HOST)
print("TLS:", ss.version(), ss.cipher()[0])

clientid = str(uuid.uuid4()).upper()
req = (
    "GET /vpntunnel HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "User-Agent: openarrayvpn-probe/0.1\r\n"
    "Cookie: " + COOKIE + "\r\n"
    "appid: SSPVPN\r\n"
    f"clientid: {clientid}\r\n"
    f"cpuid: {clientid}\r\n"
    "hostname: probe-mac\r\n"
    "payload-ip-version: 6\r\n"
    "x-devtype: 6\r\n"
    "\r\n"
)
ss.sendall(req.encode())
head, rest = read_response_head(ss)
print("=== /vpntunnel response head ===")
print(head)
print("=== bytes after head ===", rest[:64].hex() if rest else "(none)")

if " 200" not in head.split("\r\n")[0] and " 201" not in head.split("\r\n")[0]:
    print("tunnel refused, aborting")
    sys.exit(1)

print("=== send conf50 ===")
ss.sendall(conf50)
r = read_some(ss)
print("resp len", len(r), "first16:", r[:16].hex())
if len(r) > 16:
    print("json:", r[16:].decode(errors="replace"))

print("=== send conf54 ===")
ss.sendall(conf54)
r = read_some(ss)
print("resp len", len(r), "first16:", r[:16].hex())
if len(r) > 16:
    print("json:", r[16:].decode(errors="replace"))

print("=== listen 5s for pushed packets ===")
ss.settimeout(5)
t0 = time.time()
while time.time() - t0 < 5:
    try:
        d = ss.recv(65536)
        if not d:
            print("EOF")
            break
        print("push:", len(d), d[:40].hex())
    except socket.timeout:
        break

ss.close()
print("done")

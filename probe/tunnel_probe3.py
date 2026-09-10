#!/usr/bin/env python3
"""Probe 3: raw TCP/UDP/ICMP through the tunnel.
Fresh login, then send hand-built packets to several targets and report
what comes back. Tests whether TCP works at all at the packet level."""
import socket, ssl, struct, time, json, http.client, uuid
from urllib.parse import urlencode
from http.cookies import SimpleCookie

import os

HOST = "arrayvpn.pku.edu.cn"
USER = os.environ["OAV_USER"]
PASS = os.environ["OAV_PASS"]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def https_conn():
    return http.client.HTTPSConnection(HOST, context=ctx, timeout=20)

cookies = {}
def save_cookies(resp):
    for h, v in resp.getheaders():
        if h.lower() == "set-cookie":
            c = SimpleCookie(v)
            for k, m in c.items():
                cookies[k] = m.value

def cookie_hdr():
    return "; ".join(f"{k}={v}" for k, v in cookies.items())

# login
c = https_conn()
c.request("GET", "/prx/000/http/localhost/login")
r = c.getresponse(); r.read(); save_cookies(r); c.close()
c = https_conn()
body = urlencode({"method": "北京大学VPN", "uname": USER, "pwd": PASS,
                  "pwd1": "", "pwd2": "", "deviceid": "", "device_name": "",
                  "hardwareid": "", "customer1": ""})
c.request("POST", "/prx/000/http/localhost/login", body,
          {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie_hdr()})
r = c.getresponse(); r.read(); save_cookies(r)
loc = r.getheader("Location", "")
c.close()
print("login ->", r.status, loc)
assert "/welcome" in loc, "challenge or failure"

# tunnel
conf50 = bytes([0x50]+[0]*15)
conf54 = bytes([0x54]+[0]*11+[0x20,0,0,0,0x01,0,0,0,0x0a,0,0x02,0x0f,0]+[0]*16+[0x52,0x54,0,0xde,0xa2,0xa6,0,0])

raw = socket.create_connection((HOST, 443), timeout=15)
ss = ctx.wrap_socket(raw, server_hostname=HOST)
cid = str(uuid.uuid4()).upper()
ss.sendall((f"GET /vpntunnel HTTP/1.1\r\nHost: {HOST}\r\nCookie: {cookie_hdr()}\r\n"
            f"appid: SSPVPN\r\nclientid: {cid}\r\ncpuid: {cid}\r\nhostname: probe\r\n"
            f"payload-ip-version: 6\r\nx-devtype: 6\r\n\r\n").encode())
buf = b""
while b"\r\n\r\n" not in buf:
    buf += ss.recv(4096)
print("tunnel:", buf.split(b"\r\n")[0].decode())

def xchg(req):
    ss.sendall(req)
    hdr = b""
    while len(hdr) < 16: hdr += ss.recv(16 - len(hdr))
    n = struct.unpack("<I", hdr[12:16])[0]
    pl = b""
    while len(pl) < n: pl += ss.recv(n - len(pl))
    return json.loads(pl.rstrip(b"\0"))

c1 = xchg(conf50)
c2 = xchg(conf54)
client_ip = socket.inet_ntoa(struct.pack("<I", c2["client_ipv4"]))
print("client ip:", client_ip, "keepalive:", c1["keepalive_interval"])

def csum(data):
    if len(data) % 2: data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def ip_pkt(src, dst, proto, payload):
    total = 20 + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1000, 0, 64, proto, 0) + \
         socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + payload

def tcp_syn(src, dst, dport):
    sport = 41000 + dport % 100
    seq = 0x12340000 + dport
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 0x50, 0x02, 65535, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    return ip_pkt(src, dst, 6, tcp)

def icmp_echo(src, dst):
    payload = struct.pack("!BBHHH", 8, 0, 0, 0xbeef, 1) + b"probe"
    payload = payload[:2] + struct.pack("!H", csum(payload)) + payload[4:]
    return ip_pkt(src, dst, 1, payload)

targets = [
    ("tcp", "162.105.129.65", 80),   # 校内
    ("tcp", "162.105.129.27", 53),   # 校内 DNS
    ("tcp", "222.29.159.227", 443),  # VPN 网关自身
    ("tcp", "39.156.70.37", 443),    # 校外：百度
    ("icmp", "162.105.129.27", 0),
    ("icmp", "222.29.27.1", 0),      # gateway-ish self subnet
]
for kind, ip, port in targets:
    if kind == "tcp":
        ss.sendall(tcp_syn(client_ip, ip, port))
    else:
        ss.sendall(icmp_echo(client_ip, ip))
    print(f"sent {kind} -> {ip}:{port}")

print("=== listening 15s ===")
ss.settimeout(1)
t0 = time.time()
while time.time() - t0 < 15:
    try:
        d = ss.recv(65536)
    except socket.timeout:
        continue
    if not d:
        print("EOF"); break
    while len(d) >= 20:
        iplen = struct.unpack("!H", d[2:4])[0]
        if iplen > len(d): break
        proto, src, dst = d[9], socket.inet_ntoa(d[12:16]), socket.inet_ntoa(d[16:20])
        if proto == 0xff:
            print(f"  CTRL type={struct.unpack('!H', d[12:14])[0]}")
        elif proto == 6:
            flags = d[33]
            sport, dport = struct.unpack("!HH", d[20:24])
            print(f"  TCP {src}:{sport} -> {dst}:{dport} flags={flags:#x} len={iplen}")
        elif proto == 1:
            print(f"  ICMP type={d[20]} {src} -> {dst}")
        elif proto == 17:
            print(f"  UDP {src} -> {dst} len={iplen}")
        else:
            print(f"  proto={proto} {src} -> {dst} len={iplen}")
        d = d[iplen:]
ss.close()
print("done")

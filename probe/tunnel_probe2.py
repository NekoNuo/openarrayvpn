#!/usr/bin/env python3
"""Probe 2: full tunnel + real data plane test.
Sends a UDP DNS query (www.pku.edu.cn A) through the tunnel to the
VPN-provided DNS server, prints every IP packet received."""
import socket, ssl, struct, sys, uuid, time, json

HOST = "arrayvpn.pku.edu.cn"
COOKIE = open("/tmp/av_cookie_str.txt").read().strip()

conf50 = bytes([0x50,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0])
conf54 = bytes([0x54,0,0,0, 0,0,0,0, 0,0,0,0, 0x20,0,0,0,
                0x01,0,0,0, 0x0a,0,0x02,0x0f,0,
                0,0,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
                0x52,0x54,0,0xde, 0xa2,0xa6,0,0])

def csum(data):
    if len(data) % 2: data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def ip_from_wrong_endian(n):
    return socket.inet_ntoa(struct.pack("<I", n))

def build_dns_query(src_ip, dst_ip, name):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    sport, dport = 40531, 53
    udp_len = 8 + len(dns)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + dns
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 17, udp_len)
    ucs = csum(pseudo + udp)
    udp = struct.pack("!HHHH", sport, dport, udp_len, ucs) + dns
    total = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x4242, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + udp

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=15), server_hostname=HOST)

clientid = str(uuid.uuid4()).upper()
ss.sendall((
    "GET /vpntunnel HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Cookie: " + COOKIE + "\r\n"
    "appid: SSPVPN\r\n"
    f"clientid: {clientid}\r\n"
    f"cpuid: {clientid}\r\n"
    "hostname: probe-mac\r\n"
    "payload-ip-version: 6\r\n"
    "x-devtype: 6\r\n\r\n").encode())

buf = b""
while b"\r\n\r\n" not in buf:
    buf += ss.recv(4096)
head, _, rest = buf.partition(b"\r\n\r\n")
status = head.split(b"\r\n")[0].decode()
print("tunnel:", status)
assert "200" in status or "201" in status

ss.sendall(conf50)
r = ss.recv(65536)
cfg1, _ = json.JSONDecoder().raw_decode(r[16:].decode())
print("conf50:", cfg1)

ss.sendall(conf54)
r = ss.recv(65536)
cfg2, _ = json.JSONDecoder().raw_decode(r[16:].decode())
client_ip = ip_from_wrong_endian(cfg2["client_ipv4"])
mask = ip_from_wrong_endian(cfg2["client_ipv4_mask"])
dns_ip = ip_from_wrong_endian(cfg2["dns_servers"][0]["ipv4"][0])
print(f"client_ip={client_ip} mask={mask} dns={dns_ip}")
print("routes:")
for rr in cfg2["include_network_resource"]["ipv4"]:
    print("  ", ip_from_wrong_endian(rr["ip"]), "/", ip_from_wrong_endian(rr["mask"]))

pkt = build_dns_query(client_ip, dns_ip, "www.pku.edu.cn")
print("=== sending DNS query packet ===")
ss.sendall(pkt)

ss.settimeout(1)
t0 = time.time()
while time.time() - t0 < 10:
    try:
        d = ss.recv(65536)
    except socket.timeout:
        continue
    if not d:
        print("EOF"); break
    # packets may be batched / split; simple parse for probe
    while len(d) >= 20:
        iplen = struct.unpack("!H", d[2:4])[0]
        proto = d[9]
        src = socket.inet_ntoa(d[12:16]); dst = socket.inet_ntoa(d[16:20])
        tag = "CTRL" if proto == 0xff else ("UDP" if proto == 17 else ("TCP" if proto == 6 else f"p{proto}"))
        print(f"  pkt {tag} {src} -> {dst} len={iplen}")
        if proto == 17 and len(d) >= iplen:
            udp = d[20:iplen]
            if len(udp) > 12:
                print("    udp payload:", udp[8:60].hex())
        if iplen >= len(d):
            break
        d = d[iplen:]
print("done")
ss.close()

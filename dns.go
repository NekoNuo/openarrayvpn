package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// lookupViaTunnel sends a DNS query through the userspace stack to the
// VPN-provided DNS server and returns A/AAAA records.
func lookupViaTunnel(st *Stack, server net.IP, name string) ([]net.IP, error) {
	var id [2]byte
	rand.Read(id[:])

	q := buildDNSQuery(id, name)
	raddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4([4]byte{server[0], server[1], server[2], server[3]}),
		Port: 53,
	}
	conn, err := gonet.DialUDP(st.s, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(buf[:n], id)
}

func buildDNSQuery(id [2]byte, name string) []byte {
	var q []byte
	q = append(q, id[:]...)
	q = append(q, 0x01, 0x00) // RD
	q = append(q, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	// ask for A; the answer section may also contain CNAME chains
	q = append(q, 0, 1, 0, 1)
	return q
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func parseDNSResponse(resp []byte, wantID [2]byte) ([]net.IP, error) {
	if len(resp) < 12 || resp[0] != wantID[0] || resp[1] != wantID[1] {
		return nil, fmt.Errorf("bad DNS response")
	}
	if resp[3]&0x0f != 0 {
		return nil, fmt.Errorf("DNS rcode %d", resp[3]&0x0f)
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipDNSName(resp, off)
		off += 4
		if off > len(resp) {
			return nil, fmt.Errorf("truncated question")
		}
	}
	var ips []net.IP
	for i := 0; i < an; i++ {
		off = skipDNSName(resp, off)
		if off+10 > len(resp) {
			break
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		off += 10
		if off+rdlen > len(resp) {
			break
		}
		switch typ {
		case 1:
			if rdlen == 4 {
				ips = append(ips, net.IP(resp[off:off+4]))
			}
		case 28:
			if rdlen == 16 {
				ips = append(ips, net.IP(resp[off:off+16]))
			}
		}
		off += rdlen
	}
	return ips, nil
}

func skipDNSName(b []byte, off int) int {
	for off < len(b) {
		l := int(b[off])
		if l == 0 {
			return off + 1
		}
		if l&0xc0 == 0xc0 {
			return off + 2
		}
		off += 1 + l
	}
	return off
}

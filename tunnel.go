package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// randomUUID formats 16 random bytes as an upper-case UUID, like the
// official client's clientid.
func randomUUID() string {
	var b [16]byte
	rand.Read(b[:])
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

var conf50 = []byte{0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// buildConf54 builds the 48-byte network config request: type 0x54, a 0x20
// flag at offset 12, the count and list of local IPv4 addresses (from
// offset 20, up to 5), and the local MAC at offset 40 — mirroring the
// official client (get_config.c), which fills these dynamically.
func buildConf54() []byte {
	b := make([]byte, 48)
	b[0] = 0x54
	b[12] = 0x20
	var ips []net.IP
	var mac net.HardwareAddr
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			if mac == nil && len(ifi.HardwareAddr) == 6 {
				mac = ifi.HardwareAddr
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP.To4()
				case *net.IPAddr:
					ip = v.IP.To4()
				}
				if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && len(ips) < 5 {
					ips = append(ips, ip)
				}
			}
		}
	}
	b[16] = byte(len(ips))
	for i, ip := range ips {
		copy(b[20+i*4:], ip)
	}
	if mac != nil {
		copy(b[40:46], mac)
	}
	return b
}

// dpdPkt is the keepalive/control packet (IPv4, proto 0xff, type 1).
var dpdPkt = []byte{0x45, 0, 0, 0x14, 0, 0, 0, 0,
	0, 0xff, 0, 0, 0, 1, 0, 0,
	0, 0, 0, 0}

type Tunnel struct {
	conn       *tls.Conn
	ClientIP   net.IP
	Mask       net.IPMask
	DNS        []net.IP
	Includes   []*net.IPNet
	Excludes   []*net.IPNet
	Keepalive  int
	FullTunnel bool // server set resource_group_flag&1

	wrMu    sync.Mutex
	lastTx  atomic.Int64 // unixnano
	lastRx  atomic.Int64
	expired bool
}

func (t *Tunnel) MaskString() string {
	return net.IP(t.Mask).String()
}

func (t *Tunnel) CookieExpired() bool { return t.expired }

// WritePacket sends one raw IP packet over the tunnel.
func (t *Tunnel) WritePacket(p []byte) error {
	if verbose && len(p) >= 20 && p[0]>>4 == 4 {
		log.Printf("tx %s", pktDesc(p))
	}
	t.wrMu.Lock()
	defer t.wrMu.Unlock()
	t.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := t.conn.Write(p)
	t.conn.SetWriteDeadline(time.Time{})
	if err == nil {
		t.lastTx.Store(time.Now().UnixNano())
	}
	return err
}

// pktDesc summarizes an IPv4 packet for logging.
func pktDesc(p []byte) string {
	proto := p[9]
	src := net.IP(p[12:16])
	dst := net.IP(p[16:20])
	plen := binary.BigEndian.Uint16(p[2:4])
	switch proto {
	case 6:
		if len(p) >= 40 {
			return fmt.Sprintf("TCP %s:%d -> %s:%d flags=%#x len=%d",
				src, binary.BigEndian.Uint16(p[20:22]), dst, binary.BigEndian.Uint16(p[22:24]), p[33], plen)
		}
	case 17:
		if len(p) >= 28 {
			return fmt.Sprintf("UDP %s:%d -> %s:%d len=%d",
				src, binary.BigEndian.Uint16(p[20:22]), dst, binary.BigEndian.Uint16(p[22:24]), plen)
		}
	case 1:
		return fmt.Sprintf("ICMP type=%d %s -> %s len=%d", p[20], src, dst, plen)
	case 0xff:
		return fmt.Sprintf("CTRL type=%x", binary.BigEndian.Uint16(p[12:14]))
	}
	return fmt.Sprintf("proto=%d %s -> %s len=%d", proto, src, dst, plen)
}

func (t *Tunnel) Close() { t.conn.Close() }

// ConnectTunnel establishes the TLS data channel and runs the
// conf50/conf54 JSON negotiation.
func ConnectTunnel(server, caFile, cookie string, insecure bool) (*Tunnel, error) {
	tlsCfg, err := makeTLSConfig(server, caFile, insecure)
	if err != nil {
		return nil, err
	}
	// Keep the complete authority, including IPv6 brackets and the port.
	// makeTLSConfig has already validated host:port.
	d := &net.Dialer{Timeout: 20 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", server, tlsCfg)
	if err != nil {
		return nil, err
	}

	clientID := randomUUID()
	hostname, _ := os.Hostname()
	req := fmt.Sprintf("GET /prx/000/http/localhost/vpntunnel HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Cookie: %s\r\n"+
		"appid: SSPVPN\r\n"+
		"clientid: %s\r\n"+
		"cpuid: %s\r\n"+
		"hostname: %s\r\n"+
		"payload-ip-version: 6\r\n"+
		"x-devtype: 6\r\n\r\n", server, cookie, clientID, clientID, hostname)
	// The handshake as a whole gets a deadline; cleared once established.
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	status, err := readHTTPStatus(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Per the official client (get_config.c): 201 selects the JSON config
	// protocol; 200 selects the legacy binary protocol, which this client
	// does not implement.
	if status == 200 {
		conn.Close()
		return nil, fmt.Errorf("server uses the legacy binary config protocol (HTTP 200); not supported")
	}
	if status != 201 {
		conn.Close()
		return nil, &tunnelRefusedError{status: status}
	}

	now := time.Now().UnixNano()
	t := &Tunnel{conn: conn, Keepalive: 30}
	t.lastTx.Store(now)
	t.lastRx.Store(now)

	// conf50: speed tunnel / keepalive settings
	resp, err := t.jsonExchange(conf50, 0x51)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("conf50: %w", err)
	}
	var c50 struct {
		KeepaliveInterval int `json:"keepalive_interval"`
		AllowSpeedTunnel  int `json:"allow_speed_tunnel"`
	}
	if err := json.Unmarshal(resp, &c50); err != nil {
		conn.Close()
		return nil, fmt.Errorf("conf50 JSON: %w", err)
	}
	if c50.KeepaliveInterval > 0 {
		t.Keepalive = c50.KeepaliveInterval
	}
	// allow_speed_tunnel (DTLS) is intentionally not used; the TLS
	// channel alone carries IP packets.

	// conf54: interface configuration
	resp, err = t.jsonExchange(buildConf54(), 0x55)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("conf54: %w", err)
	}
	if err := t.parseInterfaceInfo(resp); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return t, nil
}

type tunnelRefusedError struct{ status int }

func (e *tunnelRefusedError) Error() string {
	return fmt.Sprintf("vpntunnel refused: HTTP %d", e.status)
}

// readHTTPStatus reads the status line and headers of an HTTP response.
func readHTTPStatus(r io.Reader) (int, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 1)
	for !bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
		if _, err := r.Read(tmp); err != nil {
			return 0, err
		}
		buf.WriteByte(tmp[0])
		if buf.Len() > 16384 {
			return 0, fmt.Errorf("oversized HTTP header")
		}
	}
	var status int
	fmt.Sscanf(buf.String(), "HTTP/1.1 %d", &status)
	if status == 0 {
		fmt.Sscanf(buf.String(), "HTTP/1.0 %d", &status)
	}
	return status, nil
}

func (t *Tunnel) jsonExchange(req []byte, wantType byte) ([]byte, error) {
	return jsonExchangeIO(t.conn, req, wantType)
}

// jsonExchangeIO sends a fixed control structure and reads the response:
// a 16-byte header (byte 0 is the reply type, bytes 12-15 the little-endian
// payload length) followed by a NUL-padded JSON document.
func jsonExchangeIO(rw io.ReadWriter, req []byte, wantType byte) ([]byte, error) {
	if _, err := rw.Write(req); err != nil {
		return nil, err
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != wantType {
		return nil, fmt.Errorf("unexpected response type %#02x (want %#02x)", hdr[0], wantType)
	}
	n := binary.LittleEndian.Uint32(hdr[12:16])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("bad JSON length %d (header %x)", n, hdr)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(rw, payload); err != nil {
		return nil, err
	}
	payload = bytes.TrimRight(payload, "\x00")
	if len(payload) == 0 || payload[0] != '{' {
		return nil, fmt.Errorf("unexpected payload: %x", payload[:min(16, len(payload))])
	}
	return payload, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// wrongEndianIP decodes Array's little-endian-integer IPv4 encoding.
func wrongEndianIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b)
}

type incExcEntry struct {
	IP   uint32 `json:"ip"`
	Mask uint32 `json:"mask"`
}

type incExcGroup struct {
	IPv4 []incExcEntry `json:"ipv4"`
}

func (t *Tunnel) parseInterfaceInfo(payload []byte) error {
	var cfg struct {
		ClientIPv4        uint32      `json:"client_ipv4"`
		ClientIPv4Mask    uint32      `json:"client_ipv4_mask"`
		ResourceGroupFlag int         `json:"resource_group_flag"`
		Include           incExcGroup `json:"include_network_resource"`
		Exclude           incExcGroup `json:"exclude_network_resource"`
		DNSServers        []struct {
			IPv4 []uint32 `json:"ipv4"`
		} `json:"dns_servers"`
	}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return fmt.Errorf("parse interface info: %w", err)
	}
	// resource_group_flag&1: server mandates full-tunnel mode.
	t.FullTunnel = cfg.ResourceGroupFlag&1 != 0
	t.ClientIP = wrongEndianIP(cfg.ClientIPv4)
	t.Mask = net.IPMask(wrongEndianIP(cfg.ClientIPv4Mask))
	for _, e := range cfg.Include.IPv4 {
		t.Includes = append(t.Includes, &net.IPNet{IP: wrongEndianIP(e.IP), Mask: net.IPMask(wrongEndianIP(e.Mask))})
	}
	for _, e := range cfg.Exclude.IPv4 {
		t.Excludes = append(t.Excludes, &net.IPNet{IP: wrongEndianIP(e.IP), Mask: net.IPMask(wrongEndianIP(e.Mask))})
	}
	for _, d := range cfg.DNSServers {
		for _, ip := range d.IPv4 {
			t.DNS = append(t.DNS, wrongEndianIP(ip))
		}
	}
	if cfg.ClientIPv4 == 0 {
		return fmt.Errorf("no client_ipv4 in config")
	}
	return nil
}

package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Real conf54 sample captured from arrayvpn.pku.edu.cn,
// with NUL padding as the server sends it.
const conf54Sample = `{"resource_group_flag":8,"client_ipv4":119217630,"client_ipv4_mask":16777215,` +
	`"include_network_resource":{"ipv6":[],"ipv4":[{"domain":"","ip":27042,"mask":65535,"protocol":4,"port_type":2,"ports":[0,65535,0,0,0],"resource_type":1,"sandbox":0}],` +
	`"android":[]},"exclude_network_resource":{"ipv6":[],"ipv4":[],"android":null},` +
	`"dns_servers":[{"ipv4":[461466018]}],"search_domains":null}`

func TestParseInterfaceInfo(t *testing.T) {
	tun := &Tunnel{}
	if err := tun.parseInterfaceInfo([]byte(conf54Sample)); err != nil {
		t.Fatal(err)
	}
	if got := tun.ClientIP.String(); got != "222.29.27.7" {
		t.Errorf("client ip = %s, want 222.29.27.7", got)
	}
	if got := net.IP(tun.Mask).String(); got != "255.255.255.0" {
		t.Errorf("mask = %s", got)
	}
	if len(tun.DNS) != 1 || tun.DNS[0].String() != "162.105.129.27" {
		t.Errorf("dns = %v", tun.DNS)
	}
	if len(tun.Includes) != 1 || tun.Includes[0].String() != "162.105.0.0/16" {
		t.Errorf("includes = %v", tun.Includes)
	}
	if tun.FullTunnel {
		t.Error("resource_group_flag=8 must not set FullTunnel")
	}
}

func TestParseInterfaceInfoFullTunnel(t *testing.T) {
	tun := &Tunnel{}
	payload := `{"resource_group_flag":9,"client_ipv4":119217630,"client_ipv4_mask":16777215,` +
		`"include_network_resource":{"ipv4":[]},"exclude_network_resource":{"ipv4":[]},"dns_servers":[]}`
	if err := tun.parseInterfaceInfo([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if !tun.FullTunnel {
		t.Error("resource_group_flag&1 must set FullTunnel")
	}
}

func TestParseInterfaceInfoMissingIP(t *testing.T) {
	tun := &Tunnel{}
	if err := tun.parseInterfaceInfo([]byte(`{"resource_group_flag":8}`)); err == nil {
		t.Error("expected error for missing client_ipv4")
	}
}

func TestWrongEndianIP(t *testing.T) {
	if got := wrongEndianIP(67305985).String(); got != "1.2.3.4" {
		t.Errorf("wrongEndianIP = %s, want 1.2.3.4", got)
	}
}

func TestBuildConf54(t *testing.T) {
	b := buildConf54()
	if len(b) != 48 {
		t.Fatalf("conf54 len = %d, want 48", len(b))
	}
	if b[0] != 0x54 || b[12] != 0x20 {
		t.Errorf("header bytes: %x %x", b[0], b[12])
	}
	n := int(b[16])
	if n > 5 {
		t.Errorf("ip count %d > 5", n)
	}
	for i := 0; i < n; i++ {
		ip := net.IP(b[20+i*4 : 24+i*4])
		if ip.IsUnspecified() || ip.IsLoopback() {
			t.Errorf("bogus local ip %v", ip)
		}
	}
}

// scriptedRW answers a canned conf response after reading a request.
type scriptedRW struct {
	req  []byte
	resp []byte
}

func (s *scriptedRW) Write(p []byte) (int, error) {
	s.req = append(s.req, p...)
	return len(p), nil
}

func (s *scriptedRW) Read(p []byte) (int, error) {
	if len(s.resp) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.resp)
	s.resp = s.resp[n:]
	return n, nil
}

func confResponse(typ byte, json string, pad int) []byte {
	var hdr [16]byte
	hdr[0] = typ
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(json)+pad))
	out := append(hdr[:], json...)
	return append(out, make([]byte, pad)...)
}

func TestJSONExchangeOK(t *testing.T) {
	rw := &scriptedRW{resp: confResponse(0x51, `{"keepalive_interval":10}`, 5)}
	pl, err := jsonExchangeIO(rw, conf50, 0x51)
	if err != nil {
		t.Fatal(err)
	}
	if string(pl) != `{"keepalive_interval":10}` {
		t.Errorf("payload = %q", pl)
	}
}

func TestJSONExchangeWrongType(t *testing.T) {
	// 0x5e is the IPSec config response, not JSON L3.
	rw := &scriptedRW{resp: confResponse(0x5e, `{"client_ipv4":1}`, 0)}
	if _, err := jsonExchangeIO(rw, conf50, 0x51); err == nil {
		t.Error("expected type mismatch error")
	}
}

func TestControlPacket(t *testing.T) {
	// keepalive: handled, no error
	ka := []byte{0x45, 0, 0, 0x14, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	handled, err := controlPacketError(ka, 20)
	if !handled || err != nil {
		t.Errorf("keepalive: handled=%v err=%v", handled, err)
	}
	// KILL_TUNNEL reason 3
	kill := []byte{0x45, 0, 0, 0x14, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3}
	handled, err = controlPacketError(kill, 20)
	if !handled || err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Errorf("kill: handled=%v err=%v", handled, err)
	}
	// ordinary TCP packet: not control
	tcp := []byte{0x45, 0, 0, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	handled, _ = controlPacketError(tcp, 40)
	if handled {
		t.Error("TCP packet misclassified as control")
	}
}

func TestStripHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic secret")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Connection", "X-Foo, Keep-Alive")
	h.Set("X-Foo", "bar")
	h.Set("X-Ok", "keep")
	stripHopHeaders(h)
	for _, k := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "X-Foo", "Keep-Alive"} {
		if h.Get(k) != "" {
			t.Errorf("header %s leaked", k)
		}
	}
	if h.Get("X-Ok") != "keep" {
		t.Error("end-to-end header removed")
	}
}

// TestRelayBufferedPreRead: bytes read ahead into the handshake's
// bufio.Reader must still reach the remote side after relaying starts.
func TestRelayBufferedPreRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		io.WriteString(server, "A")          // consumed by the "handshake"
		time.Sleep(50 * time.Millisecond)
		io.WriteString(server, "B")          // read ahead into bufio
		io.WriteString(server, "C")          // arrives after relay starts
	}()

	br := bufio.NewReader(client)
	b := make([]byte, 1)
	if _, err := io.ReadFull(br, b); err != nil || b[0] != 'A' {
		t.Fatalf("handshake read: %v %q", err, b)
	}

	dst, dstOther := net.Pipe()
	defer dstOther.Close()
	// src side: MultiReader over pre-buffered data + live conn
	done := make(chan struct{})
	go func() {
		relay(io.MultiReader(br, client), client, dst)
		close(done)
	}()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(dstOther, buf); err != nil {
		t.Fatalf("read relayed data: %v", err)
	}
	if string(buf) != "BC" {
		t.Errorf("relayed %q, want %q (buffered + live)", buf, "BC")
	}
	server.Close() // EOF on the src direction
	dst.Close()    // end the other direction so relay can return
	<-done
}

// TestRelayHalfClose: after one direction EOFs, the other direction must
// still deliver in-flight data before relay returns.
func TestRelayHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type pair struct{ a, b net.Conn }
	mk := func() pair {
		c, _ := net.Dial("tcp", ln.Addr().String())
		s, _ := ln.Accept()
		return pair{c, s}
	}

	p1 := mk() // proxy<->client
	p2 := mk() // proxy<->remote

	go relay(p1.b, p1.b, p2.b)

	// client sends request then half-closes its write side
	io.WriteString(p1.a, "request")
	p1.a.(*net.TCPConn).CloseWrite()

	// remote reads request, then sends a large response
	buf := make([]byte, 7)
	if _, err := io.ReadFull(p2.a, buf); err != nil {
		t.Fatalf("remote read: %v", err)
	}
	big := strings.Repeat("x", 1<<20)
	io.WriteString(p2.a, big)
	p2.a.(*net.TCPConn).CloseWrite()

	data, err := io.ReadAll(p1.a)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(big) {
		t.Errorf("response truncated: got %d, want %d", len(data), len(big))
	}
}

func TestPlanDialReclassifiesAfterMerge(t *testing.T) {
	// Full tunnel, exclude 1.2.3.0/24. Tunnel DNS returns an excluded
	// address; system DNS returns a normal one. The merged candidate
	// must be classified: 5.6.7.8 tunnels, 1.2.3.4 stays direct.
	tun := &Tunnel{FullTunnel: true}
	tun.Excludes = []*net.IPNet{{IP: net.ParseIP("1.2.3.0"), Mask: net.CIDRMask(24, 32)}}
	d := &SmartDialer{tun: tun}
	tunnel, direct, err := d.planDial(
		[]net.IP{net.ParseIP("1.2.3.4")},
		[]net.IP{net.ParseIP("5.6.7.8")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnel) != 1 || !tunnel[0].Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("tunnel = %v, want [5.6.7.8]", tunnel)
	}
	if len(direct) != 1 || !direct[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("direct = %v, want [1.2.3.4]", direct)
	}
}

func TestPlanDialKeepsAllCandidates(t *testing.T) {
	tun := &Tunnel{}
	tun.parseInterfaceInfo([]byte(conf54Sample)) // split mode
	d := &SmartDialer{tun: tun}
	tunnel, direct, err := d.planDial(
		[]net.IP{net.ParseIP("9.9.9.9"), net.ParseIP("8.8.8.8")},
		[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("7.7.7.7")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnel) != 0 {
		t.Errorf("tunnel = %v, want empty", tunnel)
	}
	want := []string{"9.9.9.9", "8.8.8.8", "7.7.7.7"}
	if len(direct) != len(want) {
		t.Fatalf("direct = %v, want %v", direct, want)
	}
	for i, ip := range direct {
		if ip.String() != want[i] {
			t.Errorf("direct[%d] = %s, want %s", i, ip, want[i])
		}
	}
}

func TestPlanDialIPv6SkippedNotFatal(t *testing.T) {
	tun := &Tunnel{FullTunnel: true}
	d := &SmartDialer{tun: tun}
	// Dual-stack result in full-tunnel mode: v6 skipped, v4 tunnels.
	tunnel, direct, err := d.planDial(
		[]net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("1.1.1.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 0 {
		t.Errorf("direct = %v, want empty in full tunnel", direct)
	}
	if len(tunnel) != 1 || !tunnel[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("tunnel = %v, want [1.1.1.1]", tunnel)
	}
	// Only IPv6 available: clean error, not a silent direct leak.
	_, _, err = d.planDial([]net.IP{net.ParseIP("2001:db8::1")}, nil)
	if err == nil {
		t.Error("expected no-usable-address error")
	}
}

func TestDefinesChallengeVar(t *testing.T) {
	// A page that merely references the variable does not define it.
	page := `<script>document.write(_AN_str_info_chal);</script>`
	if definesChallengeVar(page) {
		t.Error("document.write reference must not count as definition")
	}
	// Real definition with a non-empty value counts.
	def := `var _AN_str_info_chal = "补充额外凭据，4位缺位电话号码：[178****9660]";`
	if !definesChallengeVar(def) {
		t.Error("real definition not detected")
	}
	// Empty definition does not count (server had nothing to ask).
	if definesChallengeVar(`var _AN_str_info_chal = "";`) {
		t.Error("empty definition must not count")
	}
}

func TestStripHopHeadersMultiConnection(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "X-Foo")
	h.Add("Connection", "X-Bar, keep-alive")
	h.Set("X-Foo", "a")
	h.Set("X-Bar", "b")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Ok", "keep")
	stripHopHeaders(h)
	for _, k := range []string{"Connection", "X-Foo", "X-Bar", "Keep-Alive"} {
		if h.Get(k) != "" {
			t.Errorf("header %s leaked", k)
		}
	}
	if h.Get("X-Ok") != "keep" {
		t.Error("end-to-end header removed")
	}
}

func TestDialerClassification(t *testing.T) {
	tun := &Tunnel{}
	tun.parseInterfaceInfo([]byte(conf54Sample))
	d := &SmartDialer{tun: tun}

	if !d.inTunnel(net.ParseIP("162.105.1.1")) {
		t.Error("162.105.1.1 should be in tunnel")
	}
	if d.inTunnel(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be direct in split mode")
	}

	// exclude list wins
	tun.Excludes = []*net.IPNet{{IP: net.ParseIP("162.105.9.0"), Mask: net.CIDRMask(24, 32)}}
	if d.inTunnel(net.ParseIP("162.105.9.9")) {
		t.Error("excluded address should be direct")
	}

	// full tunnel via server flag
	tun.FullTunnel = true
	if !d.inTunnel(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be in tunnel in full-tunnel mode")
	}
	if d.inTunnel(net.ParseIP("162.105.9.9")) {
		t.Error("excluded address stays direct in full-tunnel mode")
	}
}

func TestDialIPv6OnlyFullTunnel(t *testing.T) {
	tun := &Tunnel{FullTunnel: true}
	d := &SmartDialer{tun: tun}
	_, err := d.Dial(t.Context(), "tcp", "2001:db8::1", 443)
	if err == nil {
		t.Error("IPv6-only literal in full-tunnel mode must fail, not go direct")
	}
}

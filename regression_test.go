package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func isolatedPins(t *testing.T) string {
	t.Helper()
	old := tofuPinPath
	tofuPinPath = filepath.Join(t.TempDir(), "known_servers")
	t.Cleanup(func() { tofuPinPath = old })
	return tofuPinPath
}

func TestPinReadFailureDoesNotTrustReplacement(t *testing.T) {
	path := isolatedPins(t)
	cfg, err := makeTLSConfig("vpn.test:443", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("trusted")}, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0200); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("process can read write-only files")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("replacement")}, nil); err == nil {
		t.Fatal("accepted a new certificate when existing pins were unreadable")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("trusted pins changed: %v", err)
	}
}

func TestCorruptPinsFailClosed(t *testing.T) {
	path := isolatedPins(t)
	for _, data := range []string{"vpn.test\n", "vpn.test not-a-fingerprint\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := makeTLSConfig("vpn.test:443", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.VerifyPeerCertificate([][]byte{[]byte("new")}, nil); err == nil {
			t.Fatal("accepted malformed trust store")
		}
	}
}

func TestIPv6ServersHaveIndependentPins(t *testing.T) {
	path := isolatedPins(t)
	for _, host := range []string{"2001:db8::1", "2001:db8::2"} {
		cfg, err := makeTLSConfig(net.JoinHostPort(host, "443"), "", false)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != host {
			t.Fatalf("ServerName=%q", cfg.ServerName)
		}
		if err := cfg.VerifyPeerCertificate([][]byte{[]byte(host)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	pins, err := loadPins(path)
	if err != nil || len(pins) != 2 {
		t.Fatalf("pins=%v, error=%v", pins, err)
	}
}

func TestIPv6TunnelHTTPAuthority(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	authority := ln.Addr().String()
	observed := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Host + " " + r.URL.Path
		c, br, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "HTTP/1.1 201 OK\r\n\r\n")
		if _, err := io.ReadFull(br, make([]byte, 16)); err != nil {
			return
		}
		c.Write(confResponse(0x51, `{"keepalive_interval":10}`, 0))
		if _, err := io.ReadFull(br, make([]byte, 48)); err != nil {
			return
		}
		c.Write(confResponse(0x55, conf54Sample, 2))
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	defer srv.Close()
	tun, err := ConnectTunnel(authority, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if got := <-observed; got != authority+" /prx/000/http/localhost/vpntunnel" {
		t.Fatalf("incorrect HTTP authority/path: %q", got)
	}
}

// No outbound pump: external destinations silently drop packets, while
// addresses owned by this stack still support real local TCP/UDP traffic.
func blackholeStack(t *testing.T) *Stack {
	t.Helper()
	s := stack.New(stack.Options{
		HandleLocal:        true,
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(128, 1400, "")
	st := &Stack{s: s, ep: ep}
	t.Cleanup(st.Close)
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return st
}

func localTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestBlackholedCandidateLeavesTimeForFallback(t *testing.T) {
	st := blackholeStack(t)
	ln := localTarget(t)
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	d := &SmartDialer{stack: st, tun: &Tunnel{Includes: []*net.IPNet{subnet}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := d.dialCandidates(ctx, "tcp", "test", uint16(ln.Addr().(*net.TCPAddr).Port),
		[]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("127.0.0.1")}, map[string]bool{}, 0)
	if err != nil {
		t.Fatalf("reachable fallback was starved: %v", err)
	}
	defer c.Close()
	// Cancelling an attempt must not cancel its successfully connected socket.
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	peer.Write([]byte("ok"))
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
		t.Fatalf("connected socket unusable: %v", err)
	}
}

func TestSuccessfulTunnelDNSNeverWaitsForSystemDNS(t *testing.T) {
	st := blackholeStack(t)
	ln := localTarget(t)
	local := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), Port: 53}
	dns, err := gonet.DialUDP(st.s, &local, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		n, addr, err := dns.ReadFrom(buf)
		if err != nil {
			return
		}
		r := append([]byte(nil), buf[:n]...)
		r[2], r[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(r[6:8], 1)
		r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
		dns.WriteTo(r, addr)
	}()
	t.Cleanup(func() { dns.Close(); <-done })
	old := net.DefaultResolver
	var calls atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
	d := &SmartDialer{stack: st, tun: &Tunnel{DNS: []net.IP{{10, 0, 0, 2}}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := d.Dial(ctx, "tcp", "internal.test", uint16(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if calls.Load() != 0 {
		t.Fatal("queried system DNS despite a successful tunnel-DNS candidate")
	}
}

func TestTunnelDNSHonorsCancellation(t *testing.T) {
	st := blackholeStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := lookupViaTunnel(ctx, st, net.IP{10, 0, 0, 1}, "unreachable.test")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("DNS cancellation ignored: %v", err)
	}
}

func TestCancelledDialDoesNotTryAnotherCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &SmartDialer{tun: &Tunnel{}}
	_, err := d.Dial(ctx, "tcp", "127.0.0.1", 22)
	if err != context.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestInvalidServerAddressRejected(t *testing.T) {
	_, err := makeTLSConfig("[::1]", "", false)
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("invalid address accepted: %v", err)
	}
}

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// SmartDialer routes connections through the tunnel or directly, based on
// the server's include/exclude route lists or full-tunnel flag.
type SmartDialer struct {
	stack    *Stack
	tun      *Tunnel
	routeAll bool // manual -route-all flag
}

func (d *SmartDialer) fullTunnel() bool { return d.routeAll || d.tun.FullTunnel }

func (d *SmartDialer) excluded(ip net.IP) bool {
	for _, n := range d.tun.Excludes {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *SmartDialer) inTunnel(ip net.IP) bool {
	if d.excluded(ip) {
		return false
	}
	if d.fullTunnel() {
		return true
	}
	for _, n := range d.tun.Includes {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve prefers the tunnel DNS (needed for internal names), falling
// back to the system resolver.
func (d *SmartDialer) Resolve(ctx context.Context, name string) ([]net.IP, error) {
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}
	for _, srv := range d.tun.DNS {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ips, err := lookupViaTunnel(ctx, d.stack, srv, name); err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", name)
}

// Dial tries tunnel-DNS answers first, classifying each final address.
// System DNS is only queried if those candidates fail; it cannot delay
// a successful internal lookup or replace an address with a fake IP.
//
//   - IPv6 never traverses the tunnel (the session provisions IPv4 only).
//     In full-tunnel mode IPv6 candidates are skipped, not fatal; split
//     mode sends them direct.
//   - Excluded ranges stay direct even in full-tunnel mode.
func (d *SmartDialer) Dial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	tried := make(map[string]bool)
	if ip := net.ParseIP(host); ip != nil {
		return d.dialCandidates(ctx, network, host, port, []net.IP{ip}, tried, 0)
	}
	var lastErr error
	for _, srv := range d.tun.DNS {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ips, err := lookupViaTunnel(ctx, d.stack, srv, host)
		if err != nil || len(ips) == 0 {
			lastErr = err
			continue
		}
		// Reserve time for system DNS and its candidates if these fail.
		conn, err := d.dialCandidates(ctx, network, host, port, ips, tried, 1)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		break
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolveCtx, cancel := attemptContext(ctx, 2, 4*time.Second)
	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("resolve %s using system DNS: %w (prior attempt: %v)", host, err, lastErr)
	}
	return d.dialCandidates(ctx, network, host, port, ips, tried, 0)
}

// attemptContext caps each operation and divides the remaining request
// budget among pending attempts. An unreachable first IP cannot consume
// the entire deadline before another address has been tried.
func attemptContext(ctx context.Context, slots int, maximum time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		if share := time.Until(deadline) / time.Duration(slots); share < maximum {
			maximum = share
		}
	}
	return context.WithTimeout(ctx, maximum)
}

func (d *SmartDialer) dialCandidates(ctx context.Context, network, host string, port uint16, ips []net.IP, tried map[string]bool, reserve int) (net.Conn, error) {
	tunnel, direct, err := d.planDial(ips, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	type candidate struct {
		ip        net.IP
		viaTunnel bool
	}
	var candidates []candidate
	for _, ip := range tunnel {
		if !tried[ip.String()] {
			candidates = append(candidates, candidate{ip, true})
		}
	}
	for _, ip := range direct {
		if !tried[ip.String()] {
			candidates = append(candidates, candidate{ip, false})
		}
	}
	var lastErr error
	for i, c := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tried[c.ip.String()] = true
		attempt, cancel := attemptContext(ctx, len(candidates)-i+reserve, 15*time.Second)
		var conn net.Conn
		var err error
		route := "direct"
		if c.viaTunnel {
			route = "via tunnel"
			conn, err = d.dialStack(attempt, network, c.ip, port)
		} else {
			conn, err = (&net.Dialer{}).DialContext(attempt, network, net.JoinHostPort(c.ip.String(), fmt.Sprint(port)))
		}
		cancel()
		if err == nil {
			log.Printf("dial %s:%d %s (%s)", host, port, route, c.ip)
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", host, port, lastErr)
	}
	return nil, fmt.Errorf("no usable address for %s", host)
}

// planDial classifies resolved candidates; every address actually dialed
// is classified, including newly resolved system-DNS fallback answers.
// Tunnel-DNS results come first so a poisoned/fake-IP system resolver
// cannot replace good answers.
func (d *SmartDialer) planDial(tIPs, sIPs []net.IP) (tunnel, direct []net.IP, err error) {
	full := d.fullTunnel()
	seen := map[string]bool{}
	for _, list := range [][]net.IP{tIPs, sIPs} {
		for _, ip := range list {
			if ip == nil || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			if ip.To4() == nil {
				if !full {
					direct = append(direct, ip)
				} // full tunnel: skip IPv6
				continue
			}
			if d.inTunnel(ip) {
				tunnel = append(tunnel, ip)
			} else if d.excluded(ip) || !full {
				direct = append(direct, ip)
			}
		}
	}
	if len(tunnel) == 0 && len(direct) == 0 {
		err = fmt.Errorf("no usable address")
	}
	return tunnel, direct, err
}

func (d *SmartDialer) dialStack(ctx context.Context, network string, ip net.IP, port uint16) (net.Conn, error) {
	var proto tcpip.NetworkProtocolNumber
	var addr tcpip.Address
	if ip4 := ip.To4(); ip4 != nil {
		proto = ipv4.ProtocolNumber
		addr = tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
	} else {
		proto = ipv6.ProtocolNumber
		var b [16]byte
		copy(b[:], ip.To16())
		addr = tcpip.AddrFrom16(b)
	}
	remote := tcpip.FullAddress{NIC: nicID, Addr: addr, Port: port}
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, err := gonet.DialTCPWithBind(ctx, d.stack.s, tcpip.FullAddress{}, remote, proto)
		if verbose {
			log.Printf("dialStack tcp %s:%d -> conn=%v err=%v", ip, port, conn != nil, err)
		}
		return conn, err
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(d.stack.s, nil, &remote, proto)
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

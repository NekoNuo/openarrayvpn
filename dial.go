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
		if ips, err := lookupViaTunnel(d.stack, srv, name); err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", name)
}

// Dial resolves the host completely, classifies every final candidate
// (tunnel-eligible IPv4 first), then dials them in order.
//
//   - IPv6 never traverses the tunnel (the session provisions IPv4 only).
//     In full-tunnel mode IPv6 candidates are skipped, not fatal; split
//     mode sends them direct.
//   - Excluded ranges stay direct even in full-tunnel mode.
func (d *SmartDialer) Dial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	var tIPs, sIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		tIPs = []net.IP{ip}
	} else {
		// Tunnel DNS first (resolves internal names), system DNS merged
		// in as additional candidates.
		for _, srv := range d.tun.DNS {
			if ips, err := lookupViaTunnel(d.stack, srv, host); err == nil && len(ips) > 0 {
				tIPs = ips
				break
			}
		}
		sIPs, _ = net.DefaultResolver.LookupIP(ctx, "ip", host)
	}

	tunnel, direct, err := d.planDial(tIPs, sIPs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}

	var lastErr error
	for _, ip := range tunnel {
		conn, err := d.dialStack(ctx, network, ip, port)
		if err == nil {
			log.Printf("dial %s:%d via tunnel (%s)", host, port, ip)
			return conn, nil
		}
		lastErr = err
	}
	for _, ip := range direct {
		dd := net.Dialer{Timeout: 15 * time.Second}
		conn, err := dd.DialContext(ctx, network, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
		if err == nil {
			log.Printf("dial %s:%d direct (%s)", host, port, ip)
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", host, port, lastErr)
	}
	return nil, fmt.Errorf("no usable address for %s", host)
}

// planDial classifies resolved candidates. Resolution must be complete
// before classification; every address actually dialed is classified.
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

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func serveMixed(addr string, app *App) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("mixed proxy listen %s: %v", addr, err)
	}
	serveMixedListener(ln, app)
}

func serveMixedListener(ln net.Listener, app *App) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleMixed(c, app)
	}
}

func handleMixed(c net.Conn, app *App) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	// Keep the same reader so sniffing cannot discard pipelined payloads.
	// Pass the original connection separately to preserve CloseWrite.
	switch head[0] {
	case 0x05:
		handleSocksReader(c, br, app)
	case 0x04: // SOCKS4 is not implemented.
		return
	default:
		handleHTTPProxyReader(c, br, app)
	}
}

func serveSocks(addr string, app *App) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("socks listen %s: %v", addr, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSocks(c, app)
	}
}

func handleSocks(c net.Conn, app *App) {
	handleSocksReader(c, bufio.NewReader(c), app)
}

func handleSocksReader(c net.Conn, br *bufio.Reader, app *App) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0x00 {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{0x05, 0xff})
		return
	}
	c.Write([]byte{0x05, 0x00})

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		socksReply(c, 0x08)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	if req[1] != 0x01 { // CONNECT only
		socksReply(c, 0x07)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := app.Dial(ctx, "tcp", host, port)
	if err != nil {
		log.Printf("socks connect %s:%d: %v", host, port, err)
		socksReply(c, 0x05)
		return
	}
	defer rc.Close()

	socksReply(c, 0x00)
	c.SetDeadline(time.Time{})
	rc.SetDeadline(time.Time{})
	// br may already hold application data read ahead during the
	// handshake; keep reading through it.
	relay(io.MultiReader(br, c), c, rc)
}

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func serveHTTPProxy(addr string, app *App) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("http proxy listen %s: %v", addr, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleHTTPProxy(c, app)
	}
}

func handleHTTPProxy(c net.Conn, app *App) {
	handleHTTPProxyReader(c, bufio.NewReader(c), app)
}

// proxyTarget accepts an authority with an optional port. Only a missing
// port gets the default; malformed and out-of-range ports are rejected.
func proxyTarget(authority string, defaultPort uint16) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host = authority[1 : len(authority)-1]
			if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
				return host, defaultPort, nil
			}
		} else if authority != "" && !strings.ContainsAny(authority, ":[]") {
			return authority, defaultPort, nil
		}
		return "", 0, fmt.Errorf("invalid proxy target %q", authority)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || host == "" {
		return "", 0, fmt.Errorf("invalid proxy target %q", authority)
	}
	return host, uint16(port), nil
}

func handleHTTPProxyReader(c net.Conn, br *bufio.Reader, app *App) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		host, port, err := proxyTarget(req.Host, 443)
		if err != nil {
			fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rc, err := app.Dial(ctx, "tcp", host, port)
		if err != nil {
			log.Printf("http CONNECT %s: %v", req.Host, err)
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer rc.Close()
		fmt.Fprintf(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		c.SetDeadline(time.Time{})
		rc.SetDeadline(time.Time{})
		relay(io.MultiReader(br, c), c, rc)
		return
	}

	// Plain HTTP proxying (absolute-URI form).
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	h, port, err := proxyTarget(host, 80)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := app.Dial(ctx, "tcp", h, port)
	if err != nil {
		log.Printf("http %s %s: %v", req.Method, host, err)
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer rc.Close()

	req.RequestURI = ""
	req.Close = true
	stripHopHeaders(req.Header)

	// Upload headers+body in the background while streaming the response
	// back, so interim replies (100 Continue) and early rejections are
	// forwarded instead of deadlocking a large upload.
	go func() {
		req.Write(rc)
		if cw, ok := rc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	c.SetDeadline(time.Time{})
	rc.SetDeadline(time.Time{})
	io.Copy(c, rc)
}

// stripHopHeaders removes hop-by-hop headers — including anything the
// Connection headers name — and never forwards proxy credentials to the
// target server.
func stripHopHeaders(h http.Header) {
	for _, conn := range h.Values("Connection") {
		for _, f := range strings.Split(conn, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}

type closeWriter interface {
	CloseWrite() error
}

// relay copies bidirectionally. When one direction hits EOF it half-closes
// the other's write side and waits for the remaining direction to finish,
// so a response in flight is not truncated.
func relay(src io.Reader, srcConn net.Conn, dst net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(w net.Conn, r io.Reader) {
		io.Copy(w, r)
		if cw, ok := w.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(dst, src)
	go cp(srcConn, dst)
	<-done
	select {
	case <-done:
	case <-time.After(30 * time.Second): // peer ignored the half-close
	}
}

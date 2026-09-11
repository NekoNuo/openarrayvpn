package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mixedTestListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{}
	app.session.Store(&Session{dialer: &SmartDialer{tun: &Tunnel{}}})
	done := make(chan struct{})
	go func() { defer close(done); serveMixedListener(ln, app) }()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln
}

func TestMixedHTTPAndSOCKS(t *testing.T) {
	proxy := mixedTestListener(t).Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mixed works") })
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(handler)
	t.Cleanup(secure.Close)
	for _, scheme := range []string{"http", "socks5h"} {
		for _, target := range []string{plain.URL, secure.URL} {
			t.Run(scheme+target, func(t *testing.T) {
				t.Parallel()
				u, _ := url.Parse(scheme + "://" + proxy)
				tr := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer tr.CloseIdleConnections()
				client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
				resp, err := client.Get(target)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				if err != nil || string(b) != "mixed works" {
					t.Fatalf("body %q: %v", b, err)
				}
			})
		}
	}
}

// Send the handshake and payload together, then half-close before the
// upstream responds. This catches both lost sniff buffers and lost CloseWrite.
func TestMixedPipelinedHalfClose(t *testing.T) {
	for _, protocol := range []string{"socks", "connect"} {
		t.Run(protocol, func(t *testing.T) {
			proxy := mixedTestListener(t).Addr().String()
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			go func() {
				c, err := upstream.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b, _ := io.ReadAll(c)
				c.Write(append([]byte("reply:"), b...))
			}()
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := strings.Repeat("payload", 2048)
			var handshake []byte
			if protocol == "socks" {
				handshake = []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
				binary.BigEndian.PutUint16(handshake[len(handshake)-2:], uint16(upstream.Addr().(*net.TCPAddr).Port))
			} else {
				handshake = []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Addr(), upstream.Addr()))
			}
			if _, err := c.Write(append(handshake, []byte(payload)...)); err != nil {
				t.Fatal(err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReader(c)
			if protocol == "socks" {
				b := make([]byte, 12)
				if _, err := io.ReadFull(br, b); err != nil {
					t.Fatal(err)
				}
				if b[0] != 5 || b[1] != 0 || b[2] != 5 || b[3] != 0 {
					t.Fatalf("reply %x", b)
				}
			} else {
				resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 200 {
					t.Fatal(resp.Status)
				}
			}
			b, err := io.ReadAll(br)
			if err != nil || string(b) != "reply:"+payload {
				t.Fatalf("response length %d: %v", len(b), err)
			}
		})
	}
}

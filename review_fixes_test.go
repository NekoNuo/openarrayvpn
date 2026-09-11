package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginSessionCookies(t *testing.T) {
	for _, value := range []string{"VPN+123_hash", "VPN%2B123_hash"} {
		for _, redirect := range []bool{false, true} {
			t.Run(value+map[bool]string{true: "/redirect", false: "/200"}[redirect], func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case strings.HasSuffix(r.URL.Path, "an_login.js"):
						io.WriteString(w, `_AN_aaa_method = [{"name":"password"}];`)
					case r.Method == "POST":
						http.SetCookie(w, &http.Cookie{Name: "ANsession", Value: value, Path: "/"})
						http.SetCookie(w, &http.Cookie{Name: "role_names", Value: "student", Path: "/"})
						if redirect {
							w.Header().Set("Location", "/welcome")
							w.WriteHeader(302)
						}
					default:
						http.SetCookie(w, &http.Cookie{Name: "ANsession", Value: "VPN", Path: "/"})
					}
				}))
				defer srv.Close()
				c, err := NewAuthClient(strings.TrimPrefix(srv.URL, "https://"), "", true)
				if err != nil {
					t.Fatal(err)
				}
				cookie, err := c.Login(context.Background(), "user", "password")
				if err != nil || !strings.Contains(cookie, value) || c.Role() != "student" {
					t.Fatalf("cookie=%q role=%q err=%v", cookie, c.Role(), err)
				}
			})
		}
	}
}

func TestProxyTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		target, host string
		port         uint16
	}{
		{"example.com", "example.com", 80}, {"example.com:443", "example.com", 443},
		{"[2001:db8::1]", "2001:db8::1", 80}, {"[::1]:65535", "::1", 65535},
	} {
		h, p, e := proxyTarget(tc.target, 80)
		if e != nil || h != tc.host || p != tc.port {
			t.Errorf("%s: %q %d %v", tc.target, h, p, e)
		}
	}
	for _, target := range []string{"", ":80", "example.com:", "example.com:0", "example.com:65536", "example.com:70000", "example.com:-1", "example.com:+80", "example.com:abc", "[::1", "[bad]", "::1"} {
		if _, _, e := proxyTarget(target, 443); e == nil {
			t.Errorf("accepted %q", target)
		}
	}
}

func TestHTTPProxyRejectsOverflow(t *testing.T) {
	for _, method := range []string{"CONNECT", "GET"} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() { defer close(done); handleHTTPProxy(a, &App{}) }()
		b.SetDeadline(time.Now().Add(3 * time.Second))
		target := "example.com:70000"
		if method == "GET" {
			target = "http://" + target + "/"
		}
		io.WriteString(b, method+" "+target+" HTTP/1.1\r\nHost: example.com:70000\r\n\r\n")
		r, e := http.ReadResponse(bufio.NewReader(b), nil)
		if e != nil {
			t.Fatal(e)
		}
		if r.StatusCode != 400 {
			t.Errorf("%s status=%d", method, r.StatusCode)
		}
		r.Body.Close()
		b.Close()
		<-done
	}
}

// Keep the underlying read in flight even after Close, so Run's join is
// checked deterministically rather than relying on goroutine scheduling.
type delayedReadConn struct {
	net.Conn
	entered, closed, release chan struct{}
	enterOnce, closeOnce     sync.Once
}

func (c *delayedReadConn) Read([]byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	<-c.release
	return 0, io.EOF
}
func (c *delayedReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *delayedReadConn) Close() error                     { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (c *delayedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *delayedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *delayedReadConn) SetWriteDeadline(time.Time) error { return nil }

func TestTunnelRunJoinsReadLoop(t *testing.T) {
	c := &delayedReadConn{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	tun := &Tunnel{conn: tls.Client(c, &tls.Config{InsecureSkipVerify: true}), Keepalive: 1}
	done := make(chan error, 1)
	go func() { done <- tun.Run(nil) }()
	select {
	case <-c.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read never started")
	}
	select {
	case <-c.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive did not close connection")
	}
	select {
	case e := <-done:
		t.Fatalf("Run returned before read finished: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
	close(c.release)
	select {
	case e := <-done:
		if e == nil || !strings.Contains(e.Error(), "dead peer") {
			t.Fatalf("error=%v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not finish")
	}
}

func TestTunnelReadErrorStopsKeepalive(t *testing.T) {
	a, b := net.Pipe()
	b.Close()
	tun := &Tunnel{conn: tls.Client(a, &tls.Config{InsecureSkipVerify: true}), Keepalive: 3600}
	done := make(chan error, 1)
	go func() { done <- tun.Run(nil) }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("expected read error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting on sleeping keepalive")
	}
}

func TestRunOnceLogsOutAfterTunnelFailure(t *testing.T) {
	var logouts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "an_login.js"):
			io.WriteString(w, `_AN_aaa_method = [{"name":"password"}];`)
		case strings.HasSuffix(r.URL.Path, "logout"):
			logouts.Add(1)
		case strings.HasSuffix(r.URL.Path, "vpntunnel"):
			w.WriteHeader(403)
		case r.Method == "POST":
			http.SetCookie(w, &http.Cookie{Name: "ANsession", Value: "VPN+123_hash", Path: "/"})
		}
	}))
	defer srv.Close()
	a := &App{cfg: &Config{Server: strings.TrimPrefix(srv.URL, "https://"), Insecure: true}}
	for i := int32(1); i <= 2; i++ {
		if e := a.runOnce(); e == nil || !strings.Contains(e.Error(), "tunnel:") {
			t.Fatalf("error=%v", e)
		}
		if n := logouts.Load(); n != i {
			t.Fatalf("logouts=%d want %d", n, i)
		}
	}
	a.Stop()
	a.Stop()
	if n := logouts.Load(); n != 2 {
		t.Fatalf("Stop repeated logout: %d", n)
	}
}

func TestAuthInvalidCAReturnsError(t *testing.T) {
	if _, e := NewAuthClient("example.com:443", t.TempDir()+"/missing.pem", false); e == nil {
		t.Fatal("expected CA error")
	}
}

func TestVerificationInputCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	defer close(release)
	done := make(chan error, 1)
	go func() {
		_, err := waitForInput(ctx, func() (string, error) { <-release; return "answer", nil })
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on terminal input")
	}
}

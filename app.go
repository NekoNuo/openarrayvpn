package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// App owns the reconnect loop and the current VPN session.
type App struct {
	cfg *Config

	session  atomic.Value // *Session, nil while reconnecting
	cancel   atomic.Value // context.CancelFunc of the in-flight runOnce
	stopInit sync.Once
	stopCh   chan struct{}
	stopped  atomic.Bool

	challengePrompt func(question string) (string, error)
}

// Session is one established tunnel plus its userspace stack.
type Session struct {
	tun    *Tunnel
	stack  *Stack
	dialer *SmartDialer
	done   chan struct{}
}

func (a *App) currentDialer() *SmartDialer {
	if s, ok := a.session.Load().(*Session); ok && s != nil {
		return s.dialer
	}
	return nil
}

func (a *App) Stop() {
	a.initStop()
	if a.stopped.Swap(true) {
		return
	}
	close(a.stopCh)
	if s, ok := a.session.Load().(*Session); ok && s != nil {
		s.tun.Close()
	}
	if cancel, ok := a.cancel.Load().(context.CancelFunc); ok && cancel != nil {
		cancel()
	}
}

func (a *App) initStop() {
	a.stopInit.Do(func() { a.stopCh = make(chan struct{}) })
}

func (a *App) Run() {
	a.initStop()

	if a.cfg.Mixed != "" {
		go serveMixed(a.cfg.Mixed, a)
	}
	if a.cfg.Socks != "" {
		go serveSocks(a.cfg.Socks, a)
	}
	if a.cfg.HTTP != "" {
		go serveHTTPProxy(a.cfg.HTTP, a)
	}

	backoff := time.Second
	for !a.stopped.Load() {
		err := a.runOnce()
		if a.stopped.Load() {
			return
		}
		log.Printf("session ended: %v; reconnecting in %s", err, backoff)
		select {
		case <-a.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *App) runOnce() error {
	a.session.Store((*Session)(nil))

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel.Store(cancel)
	defer cancel()
	if a.stopped.Load() {
		return context.Canceled
	}

	ac, err := NewAuthClient(a.cfg.Server, a.cfg.CAFile, a.cfg.Insecure)
	if err != nil {
		return err
	}
	ac.Prompt = a.challengePrompt
	cookie, err := ac.Login(ctx, a.cfg.Username, a.cfg.Password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer ac.Logout()
	if role := ac.Role(); role != "" {
		log.Printf("logged in (role: %s)", role)
	} else {
		log.Printf("logged in (server did not provide role)")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	tun, err := ConnectTunnel(a.cfg.Server, a.cfg.CAFile, cookie, a.cfg.Insecure)
	if err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	if ctx.Err() != nil {
		tun.Close()
		return ctx.Err()
	}
	log.Printf("tunnel up: client %s/%s, dns %v, %d routes, keepalive %ds",
		tun.ClientIP, tun.MaskString(), tun.DNS, len(tun.Includes), tun.Keepalive)

	st, err := NewStack(tun)
	if err != nil {
		tun.Close()
		return fmt.Errorf("stack: %w", err)
	}

	dialer := &SmartDialer{
		stack:    st,
		tun:      tun,
		routeAll: a.cfg.RouteAll,
	}
	sess := &Session{tun: tun, stack: st, dialer: dialer, done: make(chan struct{})}
	a.session.Store(sess)
	defer a.session.CompareAndSwap(sess, (*Session)(nil))
	if ctx.Err() != nil {
		tun.Close()
	}

	err = tun.Run(st) // pumps packets until the connection dies
	st.Close()
	tun.Close()

	return err
}

// Dial routes a connection through the tunnel or directly.
func (a *App) Dial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	d := a.currentDialer()
	if d == nil {
		return nil, fmt.Errorf("VPN not connected")
	}
	return d.Dial(ctx, network, host, port)
}

// Resolve looks up a hostname, preferring the tunnel DNS.
func (a *App) Resolve(ctx context.Context, name string) ([]net.IP, error) {
	d := a.currentDialer()
	if d == nil {
		return nil, fmt.Errorf("VPN not connected")
	}
	return d.Resolve(ctx, name)
}

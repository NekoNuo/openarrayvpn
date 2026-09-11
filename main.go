package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

type Config struct {
	Server   string
	Username string
	Password string
	Mixed    string
	Socks    string
	HTTP     string
	RouteAll bool
	CAFile   string
	Insecure bool
}

var verbose bool

func main() {
	var cfg Config
	flag.StringVar(&cfg.Server, "server", "arrayvpn.pku.edu.cn:443", "VPN server address")
	flag.StringVar(&cfg.Username, "u", "", "username (or env OAV_USER)")
	flag.StringVar(&cfg.Password, "p", "", "password (or env OAV_PASS; prompted if empty)")
	flag.StringVar(&cfg.Mixed, "mixed", "127.0.0.1:1080", "mixed SOCKS5/HTTP listen address (empty to disable)")
	flag.StringVar(&cfg.Socks, "socks", "", "additional SOCKS5 listen address (empty to disable)")
	flag.StringVar(&cfg.HTTP, "http", "", "additional HTTP proxy listen address (empty to disable)")
	flag.BoolVar(&cfg.RouteAll, "route-all", false, "send all traffic through the tunnel (default: only VPN subnets)")
	flag.StringVar(&cfg.CAFile, "ca", "", "CA bundle PEM for strict server certificate verification (default: TOFU pinning)")
	flag.BoolVar(&cfg.Insecure, "insecure", false, "disable all server certificate checks")
	flag.BoolVar(&verbose, "v", false, "verbose packet logging")
	flag.Parse()

	if cfg.Username == "" {
		cfg.Username = os.Getenv("OAV_USER")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("OAV_PASS")
	}
	if cfg.Username == "" {
		fmt.Fprint(os.Stderr, "Username: ")
		fmt.Scanln(&cfg.Username)
	}
	if cfg.Password == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("read password: %v", err)
		}
		cfg.Password = strings.TrimRight(string(b), "\r\n")
	}
	if _, _, err := net.SplitHostPort(cfg.Server); err != nil {
		cfg.Server = net.JoinHostPort(cfg.Server, "443")
	}

	app := &App{cfg: &cfg}
	app.challengePrompt = func(question string) (string, error) {
		// Non-interactive answers for scripted use.
		if strings.Contains(question, "电话") || strings.Contains(question, "手机号") {
			if v := os.Getenv("OAV_CHAL_PHONE"); v != "" {
				return v, nil
			}
		}
		if strings.Contains(question, "身份证") || strings.Contains(question, "护照") {
			if v := os.Getenv("OAV_CHAL_ID"); v != "" {
				return v, nil
			}
		}
		fmt.Fprintf(os.Stderr, "%s\nanswer: ", question)
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		log.Printf("shutting down...")
		app.Stop()
	}()

	log.Printf("server: %s", cfg.Server)
	if cfg.Mixed != "" {
		log.Printf("Mixed proxy (SOCKS5 + HTTP): %s", cfg.Mixed)
	}
	if cfg.Socks != "" {
		log.Printf("SOCKS5 proxy: socks5://%s", cfg.Socks)
	}
	if cfg.HTTP != "" {
		log.Printf("HTTP proxy:   http://%s", cfg.HTTP)
	}
	app.Run()
}

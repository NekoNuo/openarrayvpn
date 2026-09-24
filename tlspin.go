package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// TLS certificate policy:
//   -ca given     → verify the chain against that CA bundle (strict).
//   default       → TOFU: pin the server leaf's SHA-256 on first connect
//                   (SSH known_hosts style), reject on change. The PKU
//                   server cert is issued by a private CA ("INFOSEC
//                   Technologies"), so public-chain verification can never
//                   work; the official client doesn't verify by default
//                   either (server_cert_check_on=0).
//   -insecure     → no verification at all.
//
// -legacy-tls is orthogonal to the certificate policy: it only widens the
// handshake parameters for old Array AG firmware (see enableLegacyTLS).

// legacyRSASuites are static-RSA key exchange suites that Go no longer
// offers by default (Go 1.22+). Some Array AG firmware supports nothing else.
var legacyRSASuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
}

// enableLegacyTLS caps the handshake at TLS 1.2 (old Array AG firmware drops
// the connection on a TLS 1.3 ClientHello, which surfaces as EOF) and adds
// the static-RSA suites. Go's secure defaults stay enabled and are preferred,
// so a server that supports ECDHE still negotiates it.
func enableLegacyTLS(cfg *tls.Config) {
	cfg.MaxVersion = tls.VersionTLS12
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(legacyRSASuites))
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, id := range legacyRSASuites {
		if !slices.Contains(suites, id) {
			suites = append(suites, id)
		}
	}
	cfg.CipherSuites = suites
}

func pinFilePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "openarrayvpn", "known_servers")
}

func loadPins(path string) (map[string]string, error) {
	pins := map[string]string{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pins, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read server pins: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed server pin in %s", path)
		}
		fp, err := hex.DecodeString(fields[1])
		if err != nil || len(fp) != sha256.Size {
			return nil, fmt.Errorf("invalid fingerprint for %s in %s", fields[0], path)
		}
		if previous, ok := pins[fields[0]]; ok && previous != strings.ToLower(fields[1]) {
			return nil, fmt.Errorf("conflicting pins for %s in %s", fields[0], path)
		}
		pins[fields[0]] = strings.ToLower(fields[1])
	}
	return pins, nil
}

func savePin(path, host, fingerprint string) error {
	pins, err := loadPins(path)
	if err != nil {
		return err
	}
	pins[host] = fingerprint
	var lines []string
	for h, fp := range pins {
		lines = append(lines, h+" "+fp)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Replace atomically so an interrupted write cannot truncate trusted pins.
	f, err := os.CreateTemp(filepath.Dir(path), ".known_servers-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// tofuPinPath is a var so tests can redirect it.
var tofuPinPath = pinFilePath()
var pinMu sync.Mutex

// makeTLSConfig builds the TLS config for a server connection.
// server is host:port; insecure disables all certificate checks.
func makeTLSConfig(server, caFile string, insecure bool) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid server address %q: expected host:port", server)
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	cfg := &tls.Config{ServerName: host}

	if insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
		return cfg, nil
	}

	// TOFU pinning.
	pinPath := tofuPinPath
	cfg.InsecureSkipVerify = true // chain is privately issued; we pin instead
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		pinMu.Lock()
		defer pinMu.Unlock()
		if len(rawCerts) == 0 {
			return fmt.Errorf("server sent no certificate")
		}
		fp := hex.EncodeToString(sha256sum(rawCerts[0]))
		pins, err := loadPins(pinPath)
		if err != nil {
			return err
		}
		known, ok := pins[host]
		if !ok {
			if err := savePin(pinPath, host, fp); err != nil {
				return fmt.Errorf("save server pin: %w", err)
			}
			log.Printf("TOFU: pinned %s certificate sha256=%s (%s)", host, fp, pinPath)
			return nil
		}
		if known != fp {
			return fmt.Errorf("SERVER CERTIFICATE CHANGED for %s (pinned sha256=%s, got sha256=%s); "+
				"if PKU rotated the cert, remove %s and reconnect", host, known, fp, pinPath)
		}
		return nil
	}
	return cfg, nil
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

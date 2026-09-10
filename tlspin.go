package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

func pinFilePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "openarrayvpn", "known_servers")
}

func loadPins(path string) map[string]string {
	pins := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return pins
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			pins[fields[0]] = fields[1]
		}
	}
	return pins
}

func savePin(path, host, fingerprint string) error {
	pins := loadPins(path)
	pins[host] = fingerprint
	var lines []string
	for h, fp := range pins {
		lines = append(lines, h+" "+fp)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// tofuPinPath is a var so tests can redirect it.
var tofuPinPath = pinFilePath()

// makeTLSConfig builds the TLS config for a server connection.
// server is host:port; insecure disables all certificate checks.
func makeTLSConfig(server, caFile string, insecure bool) (*tls.Config, error) {
	host := strings.Split(server, ":")[0]
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
		if len(rawCerts) == 0 {
			return fmt.Errorf("server sent no certificate")
		}
		fp := hex.EncodeToString(sha256sum(rawCerts[0]))
		known, ok := loadPins(pinPath)[host]
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

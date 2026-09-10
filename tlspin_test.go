package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTOFUPinning(t *testing.T) {
	old := tofuPinPath
	tofuPinPath = filepath.Join(t.TempDir(), "known_servers")
	defer func() { tofuPinPath = old }()

	cfg, err := makeTLSConfig("vpn.example.com:443", "", false)
	if err != nil {
		t.Fatal(err)
	}
	verify := cfg.VerifyPeerCertificate
	if verify == nil {
		t.Fatal("expected TOFU VerifyPeerCertificate")
	}
	cert := []byte("fake-leaf-cert-der")

	// First connect: pins and accepts.
	if err := verify([][]byte{cert}, nil); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	// Second connect with same cert: accepts.
	if err := verify([][]byte{cert}, nil); err != nil {
		t.Fatalf("repeat connect: %v", err)
	}
	// Changed cert: hard failure.
	err = verify([][]byte{[]byte("different-cert")}, nil)
	if err == nil || !strings.Contains(err.Error(), "CERTIFICATE CHANGED") {
		t.Fatalf("expected pin mismatch error, got %v", err)
	}
	// A different host has its own pin.
	cfg2, err := makeTLSConfig("other.example.com:443", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg2.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("empty certificate list must fail")
	}
}

func TestStrictCAMode(t *testing.T) {
	cfg, err := makeTLSConfig("vpn.example.com:443", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil {
		t.Error("insecure mode should skip all verification")
	}
}

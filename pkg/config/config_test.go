package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"
)

func TestConfigManager(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)

	configContent := `
# This is a comment
ports=10000,10001
ip=10.0.0.1/24
10.0.0.2=` + pubHex + ` # Trailing comment
`
	tmpFile := "test_server.cfg"
	if err := os.WriteFile(tmpFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	manager, err := NewManager(tmpFile)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	cfg := manager.Get()
	if len(cfg.Peers) != 1 {
		t.Fatalf("Expected 1 peer, got %d", len(cfg.Peers))
	}
	if cfg.Peers[0].PublicKey != pubHex {
		t.Errorf("Expected public key %s, got %s", pubHex, cfg.Peers[0].PublicKey)
	}
	if cfg.Peers[0].StaticIP != "10.0.0.2" {
		t.Errorf("Expected IP 10.0.0.2, got %s", cfg.Peers[0].StaticIP)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 10000 {
		t.Errorf("Expected ports [10000, 10001], got %v", cfg.Ports)
	}

	// Test Hot-Reload
	pub2, _, _ := ed25519.GenerateKey(nil)
	pubHex2 := hex.EncodeToString(pub2)
	configContent2 := "ports=20000\nip=10.1.0.1/24\n10.1.0.2=" + pubHex2 + "\n"
	
	if err := os.WriteFile(tmpFile, []byte(configContent2), 0644); err != nil {
		t.Fatalf("Failed to update temp config file: %v", err)
	}

	if err := manager.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	cfg2 := manager.Get()
	if len(cfg2.Peers) != 1 {
		t.Errorf("Expected 1 peer after reload, got %d", len(cfg2.Peers))
	}
	if cfg2.Peers[0].PublicKey != pubHex2 {
		t.Errorf("Expected updated public key %s, got %s", pubHex2, cfg2.Peers[0].PublicKey)
	}
}

func TestInvalidConfig(t *testing.T) {
	invalidConfig := "ports=10000\nip=10.0.0.1/24\n10.0.0.1=invalid_hex\n"
	tmpFile := "invalid_server.cfg"
	if err := os.WriteFile(tmpFile, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpFile)

	_, err := NewManager(tmpFile)
	if err == nil {
		t.Error("NewManager should have failed with invalid public key")
	}
}

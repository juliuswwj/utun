package config

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// PeerConfig defines the configuration for a single peer.
type PeerConfig struct {
	PublicKey string
	StaticIP  string   // Main TUN IP for this peer
	Subnets   []string // Additional subnets managed by this peer
}

// Config defines the overall server and routing configuration.
type Config struct {
	Ports   []int
	TunIP   string
	TunIP6  string
	TunName string
	Peers   []PeerConfig
}

// Manager manages the configuration with hot-reloading support.
type Manager struct {
	configPath string
	value      atomic.Value
}

// NewManager creates a new Config Manager.
func NewManager(configPath string) (*Manager, error) {
	m := &Manager{configPath: configPath}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Reload reloads the configuration from disk.
func (m *Manager) Reload() error {
	f, err := os.Open(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer f.Close()

	cfg := &Config{
		TunName: "utun0", // default
	}
	var peers []PeerConfig

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = strings.TrimSpace(line[:commentIdx])
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "ports":
			for _, p := range strings.Split(val, ",") {
				pi, err := strconv.Atoi(strings.TrimSpace(p))
				if err == nil {
					cfg.Ports = append(cfg.Ports, pi)
				}
			}
		case "ip":
			cfg.TunIP = val
		case "ip6":
			cfg.TunIP6 = val
		case "tun":
			cfg.TunName = val
		default:
			// Peer mapping: <StaticIP>=<PublicKey>[,subnet1,subnet2...]
			valParts := strings.Split(val, ",")
			pubKey := strings.TrimSpace(valParts[0])
			var subnets []string
			if len(valParts) > 1 {
				for _, s := range valParts[1:] {
					subnets = append(subnets, strings.TrimSpace(s))
				}
			}
			peers = append(peers, PeerConfig{
				StaticIP:  key,
				PublicKey: pubKey,
				Subnets:   subnets,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	cfg.Peers = peers
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	m.value.Store(cfg)
	return nil
}

// Get returns the current configuration.
func (m *Manager) Get() *Config {
	return m.value.Load().(*Config)
}

// validateConfig performs a pre-flight check on the configuration.
func validateConfig(cfg *Config) error {
	if len(cfg.Ports) == 0 {
		return fmt.Errorf("no ports specified (e.g., ports=10000,10001)")
	}
	if cfg.TunIP == "" {
		return fmt.Errorf("TUN IP missing (e.g., ip=10.0.0.1/24)")
	}

	for _, peer := range cfg.Peers {
		if _, err := hex.DecodeString(peer.PublicKey); err != nil {
			return fmt.Errorf("invalid public key hex for peer %s: %v", peer.StaticIP, err)
		}
		if len(peer.PublicKey) != ed25519.PublicKeySize*2 {
			return fmt.Errorf("invalid public key size for peer %s", peer.StaticIP)
		}
		if peer.StaticIP == "" {
			return fmt.Errorf("static IP missing for peer with public key %s", peer.PublicKey)
		}
	}
	return nil
}

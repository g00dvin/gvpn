// Command gvpn-server runs the gvpn server (serve) and generates self-signed
// certificates (gencert). It terminates GOST TLS on the configured listener and
// multiplexes authenticated clients onto one WireGuard device over a kernel TUN.
package main

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the parsed server.yaml (design §12).
type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`
	TLS struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		CA   string `yaml:"ca"`
	} `yaml:"tls"`
	WireGuard struct {
		PrivateKey string `yaml:"private_key"`
		Address    string `yaml:"address"` // server TUN CIDR, e.g. 10.100.0.1/24
	} `yaml:"wireguard"`
	Registry      string `yaml:"registry"`
	MasterKeyFile string `yaml:"master_key_file"`
}

// LoadConfig reads and validates server.yaml.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("gvpn-server: read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("gvpn-server: parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("gvpn-server: server.listen is required")
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("gvpn-server: tls.cert and tls.key are required")
	}
	if c.WireGuard.PrivateKey == "" {
		return fmt.Errorf("gvpn-server: wireguard.private_key is required")
	}
	if c.WireGuard.Address == "" {
		return fmt.Errorf("gvpn-server: wireguard.address is required")
	}
	if _, err := netip.ParsePrefix(c.WireGuard.Address); err != nil {
		return fmt.Errorf("gvpn-server: wireguard.address %q: %w", c.WireGuard.Address, err)
	}
	if c.Registry == "" {
		return fmt.Errorf("gvpn-server: registry is required")
	}
	return nil
}

// Subnet returns the tunnel subnet (the masked network of wireguard.address),
// used for enrollment IP allocation.
func (c Config) Subnet() string {
	p, err := netip.ParsePrefix(c.WireGuard.Address)
	if err != nil {
		return ""
	}
	return p.Masked().String()
}

// ServerTUNAddr returns wireguard.address as a netip.Prefix (the server's own
// tunnel address + prefix length).
func (c Config) ServerTUNAddr() (netip.Prefix, error) {
	return netip.ParsePrefix(c.WireGuard.Address)
}

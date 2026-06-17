package provision

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// User is a registry user that owns devices and holds the enrollment credential.
type User struct {
	Handle       string    `json:"handle"`
	ID           string    `json:"id"`             // 16-byte UUIDv4, canonical hex; backs enroll tokens
	EnrollPSKEnc string    `json:"enroll_psk_enc"` // AEAD(masterKey, enrollPSK)
	DeviceCap    int       `json:"device_cap"`
	EnrollOpen   bool      `json:"enroll_open"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// Device is the server-side registry record for one device (one WireGuard peer).
type Device struct {
	DeviceID   string    `json:"device_id"`
	User       string    `json:"user"`
	WGPublic   string    `json:"wg_public"`
	TunnelIP   string    `json:"tunnel_ip"`
	AuthPSKEnc string    `json:"auth_psk_enc"` // AEAD(masterKey, per-device PSK)
	CreatedAt  time.Time `json:"created_at"`
	Source     string    `json:"source"` // "admin" | "enroll"
}

// Registry is the on-disk registry: users and devices. Only *_psk_enc fields are
// secret (and encrypted); everything else is public.
type Registry struct {
	Users   []User   `json:"users"`
	Devices []Device `json:"devices"`
}

// LoadRegistry reads the registry JSON object. A missing or empty file yields an
// empty registry (not an error).
func LoadRegistry(path string) (Registry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		return Registry{}, nil
	}
	if err != nil {
		return Registry{}, err
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("provision: parse registry %q: %w", path, err)
	}
	return reg, nil
}

// SaveRegistry writes reg atomically (temp file + rename), 0600 (it contains
// encrypted PSKs).
func SaveRegistry(path string, reg Registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ParseDeviceID decodes a canonical (hyphenated) or bare hex UUID into 16 bytes.
func ParseDeviceID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return [16]byte{}, err
	}
	if len(raw) != 16 {
		return [16]byte{}, fmt.Errorf("provision: device id is %d bytes, want 16", len(raw))
	}
	var id [16]byte
	copy(id[:], raw)
	return id, nil
}

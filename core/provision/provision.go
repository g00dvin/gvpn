// Package provision mints gvpn device credentials. Generate produces a client
// Bundle (DeviceID, AUTH PSK, WireGuard keypair, server coordinates) and a
// matching server registry Device record (DeviceID, AUTH PSK, WG public key).
// The server loads the registry via FileStore to authenticate devices and
// configure WireGuard peers. Pure Go, no cgo.
package provision

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// authPSKSize is the size in bytes of the in-tunnel AUTH pre-shared key.
const authPSKSize = 32

// DeviceID is a 16-byte UUIDv4 device identifier.
type DeviceID [16]byte

// NewDeviceID generates a random UUIDv4 DeviceID.
func NewDeviceID() (DeviceID, error) {
	var id DeviceID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return DeviceID{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // variant 10xx
	return id, nil
}

// String returns the canonical 8-4-4-4-12 hyphenated hex UUID.
func (d DeviceID) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(d[0:4]), hex.EncodeToString(d[4:6]),
		hex.EncodeToString(d[6:8]), hex.EncodeToString(d[8:10]),
		hex.EncodeToString(d[10:16]))
}

// Bundle is the client-side device bundle: everything a client needs to connect.
// It contains secrets (WGPrivateKey, AuthPSK) and must be stored 0600.
type Bundle struct {
	DeviceID          string `json:"device_id"`               // UUID string
	AuthPSK           string `json:"auth_psk"`                // hex, 32 bytes
	WGPrivateKey      string `json:"wg_private_key"`          // hex, 32 bytes
	ServerWGPublicKey string `json:"server_wg_public_key"`    // hex, 32 bytes
	ServerEndpoint    string `json:"server_endpoint"`         // host:port
	ServerName        string `json:"server_name"`             // TLS server name
	ServerCAPEM       string `json:"server_ca_pem,omitempty"` // trust anchor PEM (optional)
}

// GenerateParams holds the server-side coordinates embedded into a new bundle.
type GenerateParams struct {
	ServerWGPublicKey wgengine.Key
	ServerEndpoint    string
	ServerName        string
	ServerCAPEM       string
}

// Generate mints a new device: a UUIDv4 DeviceID, a random AUTH PSK, and a
// WireGuard keypair. It returns the client Bundle and the server Device record,
// which share the DeviceID and AUTH PSK; the Device carries the WG public key
// whose private half lives only in the Bundle.
func Generate(p GenerateParams) (Bundle, Device, error) {
	id, err := NewDeviceID()
	if err != nil {
		return Bundle{}, Device{}, err
	}
	psk := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return Bundle{}, Device{}, err
	}
	wgPriv, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return Bundle{}, Device{}, err
	}
	pskHex := hex.EncodeToString(psk)
	idStr := id.String()

	bundle := Bundle{
		DeviceID:          idStr,
		AuthPSK:           pskHex,
		WGPrivateKey:      wgPriv.Hex(),
		ServerWGPublicKey: p.ServerWGPublicKey.Hex(),
		ServerEndpoint:    p.ServerEndpoint,
		ServerName:        p.ServerName,
		ServerCAPEM:       p.ServerCAPEM,
	}
	device := Device{
		DeviceID:    idStr,
		AuthPSK:     pskHex,
		WGPublicKey: wgPriv.PublicKey().Hex(),
	}
	return bundle, device, nil
}

// Marshal serializes the bundle as indented JSON.
func (b Bundle) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// ParseBundle deserializes a bundle from JSON.
func ParseBundle(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("provision: parse bundle: %w", err)
	}
	return b, nil
}

// ParseKey decodes a 32-byte hex WireGuard key.
func ParseKey(s string) (wgengine.Key, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return wgengine.Key{}, err
	}
	if len(raw) != 32 {
		return wgengine.Key{}, fmt.Errorf("provision: key is %d bytes, want 32", len(raw))
	}
	var k wgengine.Key
	copy(k[:], raw)
	return k, nil
}

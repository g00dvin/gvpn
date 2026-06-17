// Package provision mints gvpn credentials. It manages a user/device registry
// (FileStore), encrypts secrets at rest (Cipher), allocates tunnel IPs
// (AllocateIP), and emits enrollment bundles. Pure Go, no cgo.
package provision

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// authPSKSize is the size in bytes of AUTH / enrollment pre-shared keys.
const authPSKSize = 32

// DeviceID is a 16-byte UUIDv4 identifier (used for both device and user ids).
type DeviceID [16]byte

// NewDeviceID generates a random UUIDv4.
func NewDeviceID() (DeviceID, error) {
	var id DeviceID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return DeviceID{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

// String returns the canonical 8-4-4-4-12 hyphenated hex UUID.
func (d DeviceID) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(d[0:4]), hex.EncodeToString(d[4:6]),
		hex.EncodeToString(d[6:8]), hex.EncodeToString(d[8:10]),
		hex.EncodeToString(d[10:16]))
}

// Bundle is the client-side device bundle (contains secrets; store 0600).
type Bundle struct {
	DeviceID          string `json:"device_id"`
	AuthPSK           string `json:"auth_psk"`
	WGPrivateKey      string `json:"wg_private_key"`
	TunnelIP          string `json:"tunnel_ip"`
	ServerWGPublicKey string `json:"server_wg_public_key"`
	ServerEndpoint    string `json:"server_endpoint"`
	ServerName        string `json:"server_name"`
	ServerCAPEM       string `json:"server_ca_pem,omitempty"`
}

// Material is the freshly minted, still-plaintext result of Generate, ready to
// be turned into an encrypted registry Device via Record.
type Material struct {
	DeviceID string
	User     string
	TunnelIP string
	WGPublic string
	AuthPSK  []byte
}

// GenerateParams holds the server coordinates embedded into a bundle.
type GenerateParams struct {
	ServerWGPublicKey wgengine.Key
	ServerEndpoint    string
	ServerName        string
	ServerCAPEM       string
}

// Generate mints a device for user with the given tunnel IP: a UUIDv4 DeviceID,
// a random AUTH PSK, and a WireGuard keypair. It returns the client Bundle and
// the plaintext Material (for the server registry).
func Generate(user, tunnelIP string, p GenerateParams) (Bundle, Material, error) {
	id, err := NewDeviceID()
	if err != nil {
		return Bundle{}, Material{}, err
	}
	psk := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return Bundle{}, Material{}, err
	}
	wgPriv, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return Bundle{}, Material{}, err
	}
	idStr := id.String()
	bundle := Bundle{
		DeviceID:          idStr,
		AuthPSK:           hex.EncodeToString(psk),
		WGPrivateKey:      wgPriv.Hex(),
		TunnelIP:          tunnelIP,
		ServerWGPublicKey: p.ServerWGPublicKey.Hex(),
		ServerEndpoint:    p.ServerEndpoint,
		ServerName:        p.ServerName,
		ServerCAPEM:       p.ServerCAPEM,
	}
	mat := Material{
		DeviceID: idStr, User: user, TunnelIP: tunnelIP,
		WGPublic: wgPriv.PublicKey().Hex(), AuthPSK: psk,
	}
	return bundle, mat, nil
}

// Record turns Material into an encrypted registry Device. source is "admin" or
// "enroll".
func (m Material) Record(c *Cipher, source string) (Device, error) {
	enc, err := c.Seal(m.AuthPSK)
	if err != nil {
		return Device{}, err
	}
	return Device{
		DeviceID: m.DeviceID, User: m.User, WGPublic: m.WGPublic,
		TunnelIP: m.TunnelIP, AuthPSKEnc: enc, Source: source,
	}, nil
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

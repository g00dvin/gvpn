package provision

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// LoadRegistry reads the device registry JSON file (a JSON array of Device). A
// missing or empty file yields an empty registry (not an error).
func LoadRegistry(path string) ([]Device, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var devs []Device
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, fmt.Errorf("provision: parse registry %q: %w", path, err)
	}
	return devs, nil
}

// AppendDevice adds d to the registry file (creating it if absent), rejecting a
// duplicate DeviceID. The file is written 0600 (it contains AUTH PSKs).
func AppendDevice(path string, d Device) error {
	devs, err := LoadRegistry(path)
	if err != nil {
		return err
	}
	for _, e := range devs {
		if e.DeviceID == d.DeviceID {
			return fmt.Errorf("provision: device %s already registered", d.DeviceID)
		}
	}
	devs = append(devs, d)
	data, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// FileStore is an in-memory device store loaded from a registry file. It
// implements authgate.DeviceStore (DeviceID -> AUTH PSK) and resolves each
// device's WireGuard public key for the data path.
type FileStore struct {
	psk map[[16]byte][]byte
	wg  map[[16]byte]wgengine.Key
}

// NewFileStore loads the registry at path into a FileStore.
func NewFileStore(path string) (*FileStore, error) {
	devs, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	fs := &FileStore{psk: make(map[[16]byte][]byte), wg: make(map[[16]byte]wgengine.Key)}
	for _, d := range devs {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("provision: bad device_id %q: %w", d.DeviceID, err)
		}
		psk, err := hex.DecodeString(d.AuthPSK)
		if err != nil {
			return nil, fmt.Errorf("provision: bad auth_psk for %s: %w", d.DeviceID, err)
		}
		pub, err := ParseKey(d.WGPublicKey)
		if err != nil {
			return nil, fmt.Errorf("provision: bad wg_public_key for %s: %w", d.DeviceID, err)
		}
		fs.psk[id] = psk
		fs.wg[id] = pub
	}
	return fs, nil
}

// Lookup implements authgate.DeviceStore.
func (s *FileStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.psk[deviceID]
	return psk, ok
}

// WGPublicKey returns the device's registered WireGuard public key.
func (s *FileStore) WGPublicKey(deviceID [16]byte) (wgengine.Key, bool) {
	k, ok := s.wg[deviceID]
	return k, ok
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

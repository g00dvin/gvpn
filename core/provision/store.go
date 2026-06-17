package provision

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// FileStore is a read-write, mutex-guarded registry persisted to a JSON file. It
// decrypts per-device PSKs in memory so it satisfies authgate.DeviceStore; the
// master-key cipher is held in memory only.
type FileStore struct {
	path   string
	cipher *Cipher

	mu  sync.RWMutex
	reg Registry
}

// NewFileStore loads (or creates an empty) registry at path, using c to decrypt
// secrets on read and encrypt on write.
func NewFileStore(path string, c *Cipher) (*FileStore, error) {
	reg, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	return &FileStore{path: path, cipher: c, reg: reg}, nil
}

// Lookup implements authgate.DeviceStore: it returns the device's decrypted PSK.
func (s *FileStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil || id != deviceID {
			continue
		}
		psk, err := s.cipher.Open(d.AuthPSKEnc)
		if err != nil {
			return nil, false
		}
		return psk, true
	}
	return nil, false
}

// EnrollPSK returns the decrypted enrollment PSK for the user with the given
// 16-byte user id.
func (s *FileStore) EnrollPSK(userID [16]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.reg.Users {
		id, err := ParseDeviceID(u.ID)
		if err != nil || id != userID || u.Disabled {
			continue
		}
		psk, err := s.cipher.Open(u.EnrollPSKEnc)
		if err != nil {
			return nil, false
		}
		return psk, true
	}
	return nil, false
}

// WGPublicKey returns the device's registered WireGuard public key.
func (s *FileStore) WGPublicKey(deviceID [16]byte) (wgengine.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil || id != deviceID {
			continue
		}
		k, err := ParseKey(d.WGPublic)
		if err != nil {
			return wgengine.Key{}, false
		}
		return k, true
	}
	return wgengine.Key{}, false
}

// Device returns the device record (public fields).
func (s *FileStore) Device(deviceID [16]byte) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		if id, err := ParseDeviceID(d.DeviceID); err == nil && id == deviceID {
			return d, true
		}
	}
	return Device{}, false
}

// User returns the user record by handle.
func (s *FileStore) User(handle string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			return u, true
		}
	}
	return User{}, false
}

// DeviceCount returns how many devices a user owns.
func (s *FileStore) DeviceCount(handle string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, d := range s.reg.Devices {
		if d.User == handle {
			n++
		}
	}
	return n
}

// UsedIPs returns the tunnel IPs currently allocated (for AllocateIP).
func (s *FileStore) UsedIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ips := make([]string, 0, len(s.reg.Devices))
	for _, d := range s.reg.Devices {
		ips = append(ips, d.TunnelIP)
	}
	return ips
}

// AddUser creates a user with default guardrails (cap 5, enrollment open),
// mints a 16-byte user id and a random enroll PSK, persists, and returns the
// user plus the plaintext enroll PSK (the caller emits it; it is not stored
// plaintext).
func (s *FileStore) AddUser(handle string) (User, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			return User{}, nil, fmt.Errorf("provision: user %q already exists", handle)
		}
	}
	uid, err := NewDeviceID()
	if err != nil {
		return User{}, nil, err
	}
	enrollPSK := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, enrollPSK); err != nil {
		return User{}, nil, err
	}
	enc, err := s.cipher.Seal(enrollPSK)
	if err != nil {
		return User{}, nil, err
	}
	u := User{
		Handle: handle, ID: uid.String(), EnrollPSKEnc: enc,
		DeviceCap: 5, EnrollOpen: true, CreatedAt: time.Now().UTC(),
	}
	s.reg.Users = append(s.reg.Users, u)
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Users = s.reg.Users[:len(s.reg.Users)-1]
		return User{}, nil, err
	}
	return u, enrollPSK, nil
}

// RemoveUser deletes a user and all of its devices.
func (s *FileStore) RemoveUser(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := s.reg.Users[:0:0]
	found := false
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			found = true
			continue
		}
		users = append(users, u)
	}
	if !found {
		return fmt.Errorf("provision: user %q not found", handle)
	}
	devices := s.reg.Devices[:0:0]
	for _, d := range s.reg.Devices {
		if d.User != handle {
			devices = append(devices, d)
		}
	}
	prevU, prevD := s.reg.Users, s.reg.Devices
	s.reg.Users, s.reg.Devices = users, devices
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Users, s.reg.Devices = prevU, prevD
		return err
	}
	return nil
}

// AddDevice encrypts pskPlain into the record and persists it, rejecting a
// duplicate DeviceID or an unknown user.
func (s *FileStore) AddDevice(d Device, pskPlain []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userOK := false
	for _, u := range s.reg.Users {
		if u.Handle == d.User {
			userOK = true
			break
		}
	}
	if !userOK {
		return fmt.Errorf("provision: unknown user %q", d.User)
	}
	for _, e := range s.reg.Devices {
		if sameDeviceID(e.DeviceID, d.DeviceID) {
			return fmt.Errorf("provision: device %s already registered", d.DeviceID)
		}
	}
	enc, err := s.cipher.Seal(pskPlain)
	if err != nil {
		return err
	}
	d.AuthPSKEnc = enc
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	s.reg.Devices = append(s.reg.Devices, d)
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Devices = s.reg.Devices[:len(s.reg.Devices)-1]
		return err
	}
	return nil
}

// RemoveDevice deletes a device by DeviceID.
func (s *FileStore) RemoveDevice(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.reg.Devices[:0:0]
	found := false
	for _, d := range s.reg.Devices {
		if sameDeviceID(d.DeviceID, deviceID) {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return fmt.Errorf("provision: device %s not found", deviceID)
	}
	prev := s.reg.Devices
	s.reg.Devices = out
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Devices = prev
		return err
	}
	return nil
}

// sameDeviceID reports whether two device-id strings denote the same 16-byte id,
// tolerating canonical-vs-bare-hex formatting. Falls back to string equality if
// either value is not a valid id.
func sameDeviceID(a, b string) bool {
	ida, erra := ParseDeviceID(a)
	idb, errb := ParseDeviceID(b)
	if erra != nil || errb != nil {
		return a == b
	}
	return ida == idb
}

// genWGKeyHexForTest is a small helper used by store_test.go.
func genWGKeyHexForTest() (string, error) {
	k, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return k.PublicKey().Hex(), nil
}

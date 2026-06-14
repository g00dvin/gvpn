package authgate

// DeviceStore resolves a DeviceID to its AUTH pre-shared key. The gate uses it
// to find the PSK for the device a connection claims to be. Implementations
// must be safe for concurrent use by the gate.
type DeviceStore interface {
	// Lookup returns the PSK for deviceID and whether it is registered.
	Lookup(deviceID [16]byte) (psk []byte, ok bool)
}

// MapStore is an in-memory DeviceStore for phase-1 and tests. It is read-only
// after construction, so it needs no locking.
type MapStore struct {
	devices map[[16]byte][]byte
}

// NewMapStore builds a MapStore from a deviceID->PSK map (nil is allowed and
// yields an empty store). The caller must not mutate devices afterward.
func NewMapStore(devices map[[16]byte][]byte) *MapStore {
	if devices == nil {
		devices = map[[16]byte][]byte{}
	}
	return &MapStore{devices: devices}
}

// Lookup implements DeviceStore.
func (s *MapStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.devices[deviceID]
	return psk, ok
}

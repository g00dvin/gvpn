package authgate

// DeviceStore resolves credentials for the in-tunnel auth gate: a device id to
// its per-device AUTH PSK (KindDevice), and a user id to its enrollment PSK
// (KindEnroll). Implementations must be safe for concurrent use by the gate.
type DeviceStore interface {
	// Lookup returns the per-device AUTH PSK for deviceID and whether it exists.
	Lookup(deviceID [16]byte) (psk []byte, ok bool)
	// EnrollLookup returns the enrollment PSK for userID and whether that user
	// exists and may enroll.
	EnrollLookup(userID [16]byte) (psk []byte, ok bool)
}

// MapStore is an in-memory DeviceStore for phase-1 and tests. It is read-only
// after construction, so it needs no locking.
type MapStore struct {
	devices map[[16]byte][]byte
	enroll  map[[16]byte][]byte
}

// NewMapStore builds a MapStore from a deviceID->PSK map (nil is allowed and
// yields an empty store) with no enrollment users. The caller must not mutate
// the map afterward.
func NewMapStore(devices map[[16]byte][]byte) *MapStore {
	return NewMapStoreWithEnroll(devices, nil)
}

// NewMapStoreWithEnroll builds a MapStore from a deviceID->PSK map and a
// userID->enrollPSK map (either may be nil). The caller must not mutate the maps
// afterward.
func NewMapStoreWithEnroll(devices, enroll map[[16]byte][]byte) *MapStore {
	if devices == nil {
		devices = map[[16]byte][]byte{}
	}
	if enroll == nil {
		enroll = map[[16]byte][]byte{}
	}
	return &MapStore{devices: devices, enroll: enroll}
}

// Lookup implements DeviceStore.
func (s *MapStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.devices[deviceID]
	return psk, ok
}

// EnrollLookup implements DeviceStore.
func (s *MapStore) EnrollLookup(userID [16]byte) ([]byte, bool) {
	psk, ok := s.enroll[userID]
	return psk, ok
}

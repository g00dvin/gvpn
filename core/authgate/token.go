// Package authgate implements the gvpn in-tunnel authentication gate: a server
// inspects the first frame of a (GOST TLS-terminated) connection and either
// admits it to the VPN data path or reverse-proxies it to a decoy origin. It
// also provides the client-side AUTH token emitter. Pure Go, no cgo.
package authgate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// tokenVersion is the AUTH token format version, independent of the frame
// version, so PSKs/algorithms can rotate later without a frame bump.
const tokenVersion uint8 = 1

const macSize = 32 // HMAC-SHA256 output

// Token kinds select the gate path (design §6). The 16-byte id field is a
// DeviceID for KindDevice and a user id for KindEnroll.
const (
	KindDevice uint8 = 0
	KindEnroll uint8 = 1
)

// TokenSize is the exact marshaled size of an AUTH token and therefore the
// exact frame payload length the gate accepts for an AUTH frame:
// version(1) + kind(1) + id(16) + nonce(16) + timestamp(8) + mac(32).
const TokenSize = 1 + 1 + 16 + 16 + 8 + macSize // 74

// Token errors.
var (
	ErrTokenSize    = errors.New("authgate: wrong token size")
	ErrTokenVersion = errors.New("authgate: unsupported token version")
	ErrBadMAC       = errors.New("authgate: token MAC mismatch")
	ErrStale        = errors.New("authgate: token timestamp outside window")
)

// Token is the in-tunnel authentication token. Kind selects the gate path; the
// DeviceID field carries a device id (KindDevice) or a user id (KindEnroll). The
// MAC binds the kind, the id, a random nonce, and a timestamp under the relevant
// PSK, making each token high-entropy, replay-bounded, and unlinkable (§3).
type Token struct {
	Version   uint8
	Kind      uint8
	DeviceID  [16]byte
	Nonce     [16]byte
	Timestamp int64
	MAC       [macSize]byte
}

// MakeToken builds a fresh KindDevice AUTH token for deviceID under the
// per-device psk, stamped at now, and returns its marshaled form.
func MakeToken(psk []byte, deviceID [16]byte, now time.Time) ([]byte, error) {
	return makeToken(psk, KindDevice, deviceID, now)
}

// MakeEnrollToken builds a fresh KindEnroll AUTH token for userID under the
// user's enrollment psk. A new device sends it to bootstrap enrollment (§7).
func MakeEnrollToken(psk []byte, userID [16]byte, now time.Time) ([]byte, error) {
	return makeToken(psk, KindEnroll, userID, now)
}

func makeToken(psk []byte, kind uint8, id [16]byte, now time.Time) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	t := Token{Version: tokenVersion, Kind: kind, DeviceID: id, Nonce: nonce, Timestamp: now.Unix()}
	t.MAC = computeMAC(psk, t)
	return t.Marshal(), nil
}

// Marshal serializes the token to its fixed TokenSize byte layout.
func (t Token) Marshal() []byte {
	b := make([]byte, TokenSize)
	b[0] = t.Version
	b[1] = t.Kind
	copy(b[2:18], t.DeviceID[:])
	copy(b[18:34], t.Nonce[:])
	binary.BigEndian.PutUint64(b[34:42], uint64(t.Timestamp))
	copy(b[42:74], t.MAC[:])
	return b
}

// ParseToken deserializes a token from a TokenSize-length payload. It does not
// verify the MAC; call Verify for that.
func ParseToken(b []byte) (Token, error) {
	if len(b) != TokenSize {
		return Token{}, ErrTokenSize
	}
	var t Token
	t.Version = b[0]
	t.Kind = b[1]
	copy(t.DeviceID[:], b[2:18])
	copy(t.Nonce[:], b[18:34])
	t.Timestamp = int64(binary.BigEndian.Uint64(b[34:42]))
	copy(t.MAC[:], b[42:74])
	return t, nil
}

// Verify recomputes the MAC under psk (constant-time compare) and checks the
// timestamp is within window of now (in either direction, tolerating clock skew).
func (t Token) Verify(psk []byte, now time.Time, window time.Duration) error {
	if t.Version != tokenVersion {
		return ErrTokenVersion
	}
	expected := computeMAC(psk, t)
	if !hmac.Equal(expected[:], t.MAC[:]) {
		return ErrBadMAC
	}
	skew := now.Sub(time.Unix(t.Timestamp, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return ErrStale
	}
	return nil
}

// computeMAC = HMAC-SHA256(psk, version || kind || id || nonce || timestamp).
func computeMAC(psk []byte, t Token) [macSize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{t.Version, t.Kind})
	mac.Write(t.DeviceID[:])
	mac.Write(t.Nonce[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.Timestamp))
	mac.Write(ts[:])
	var out [macSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

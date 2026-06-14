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

// TokenSize is the exact marshaled size of an AUTH token and therefore the
// exact frame payload length the gate accepts for an AUTH frame:
// version(1) + deviceID(16) + nonce(16) + timestamp(8) + mac(32).
const TokenSize = 1 + 16 + 16 + 8 + macSize // 73

// Token errors.
var (
	ErrTokenSize    = errors.New("authgate: wrong token size")
	ErrTokenVersion = errors.New("authgate: unsupported token version")
	ErrBadMAC       = errors.New("authgate: token MAC mismatch")
	ErrStale        = errors.New("authgate: token timestamp outside window")
)

// Token is the in-tunnel authentication token. The MAC binds the device, a
// random nonce, and a timestamp under the device PSK, making each token
// high-entropy, replay-bounded, and unlinkable (design §3).
type Token struct {
	Version   uint8
	DeviceID  [16]byte
	Nonce     [16]byte
	Timestamp int64
	MAC       [macSize]byte
}

// MakeToken builds a fresh AUTH token for deviceID under psk, stamped at now,
// and returns its marshaled form (use it as a frame.TypeAuth payload).
func MakeToken(psk []byte, deviceID [16]byte, now time.Time) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	t := Token{Version: tokenVersion, DeviceID: deviceID, Nonce: nonce, Timestamp: now.Unix()}
	t.MAC = computeMAC(psk, t)
	return t.Marshal(), nil
}

// Marshal serializes the token to its fixed TokenSize byte layout.
func (t Token) Marshal() []byte {
	b := make([]byte, TokenSize)
	b[0] = t.Version
	copy(b[1:17], t.DeviceID[:])
	copy(b[17:33], t.Nonce[:])
	binary.BigEndian.PutUint64(b[33:41], uint64(t.Timestamp))
	copy(b[41:73], t.MAC[:])
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
	copy(t.DeviceID[:], b[1:17])
	copy(t.Nonce[:], b[17:33])
	t.Timestamp = int64(binary.BigEndian.Uint64(b[33:41]))
	copy(t.MAC[:], b[41:73])
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

// computeMAC = HMAC-SHA256(psk, version || deviceID || nonce || timestamp).
func computeMAC(psk []byte, t Token) [macSize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{t.Version})
	mac.Write(t.DeviceID[:])
	mac.Write(t.Nonce[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.Timestamp))
	mac.Write(ts[:])
	var out [macSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

package wgengine

import (
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/crypto/curve25519"
)

// Key is a 32-byte Curve25519 key (WireGuard private or public).
type Key [32]byte

// GeneratePrivateKey returns a new, clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	// Curve25519 clamping.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// PublicKey derives the Curve25519 public key for this private key.
func (k Key) PublicKey() Key {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 only errors on low-order inputs; the basepoint is valid and a
		// clamped key is non-zero, so this is unreachable in practice.
		panic("wgengine: deriving public key: " + err.Error())
	}
	var out Key
	copy(out[:], pub)
	return out
}

// Hex returns the lowercase hex encoding used by the WireGuard UAPI.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

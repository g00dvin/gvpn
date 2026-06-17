package provision

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher encrypts at-rest secrets (device/enroll PSKs) with XChaCha20-Poly1305
// under a 32-byte master key. Stored form is base64(nonce || ciphertext).
type Cipher struct{ aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
} }

// NewCipher builds a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("provision: cipher: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// NewCipherFromHex builds a Cipher from a 64-char hex key.
func NewCipherFromHex(h string) (*Cipher, error) {
	key, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("provision: master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("provision: master key is %d bytes, want 32", len(key))
	}
	return NewCipher(key)
}

// Seal encrypts plain and returns base64(nonce || ciphertext).
func (c *Cipher) Seal(plain []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := c.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal.
func (c *Cipher) Open(enc string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("provision: cipher base64: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("provision: ciphertext too short")
	}
	return c.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// LoadMasterKey returns the 32-byte master key from GVPN_MASTER_KEY (64 hex
// chars) or, if that is empty, from the file at keyFile (64 hex chars).
func LoadMasterKey(keyFile string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("GVPN_MASTER_KEY")); env != "" {
		return decodeKey(env)
	}
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("provision: read master key file: %w", err)
		}
		return decodeKey(string(raw))
	}
	return nil, errors.New("provision: no master key (set GVPN_MASTER_KEY or pass a key file)")
}

func decodeKey(h string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("provision: master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("provision: master key is %d bytes, want 32", len(key))
	}
	return key, nil
}

package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// shareTokenStore maps opaque, TTL'd, revocable share tokens to a user handle.
// The token (not the enrollment PSK) appears in share URLs; the share page
// renders the real gvpn://enroll URI only after a valid token resolves.
type shareTokenStore struct {
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	tokens map[string]shareTokenEntry
}

type shareTokenEntry struct {
	handle string
	expiry time.Time
}

func newShareTokenStore(ttl time.Duration) *shareTokenStore {
	return &shareTokenStore{ttl: ttl, now: time.Now, tokens: make(map[string]shareTokenEntry)}
}

// Mint creates a fresh token for handle, valid for the store's TTL.
func (s *shareTokenStore) Mint(handle string) (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	s.tokens[tok] = shareTokenEntry{handle: handle, expiry: s.now().Add(s.ttl)}
	s.mu.Unlock()
	return tok, nil
}

// Resolve returns the handle for a valid, unexpired token. An expired token is
// dropped opportunistically.
func (s *shareTokenStore) Resolve(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[tok]
	if !ok {
		return "", false
	}
	if s.now().After(e.expiry) {
		delete(s.tokens, tok)
		return "", false
	}
	return e.handle, true
}

// Revoke drops a token immediately.
func (s *shareTokenStore) Revoke(tok string) {
	s.mu.Lock()
	delete(s.tokens, tok)
	s.mu.Unlock()
}

// Sweep removes expired tokens. A server may call it periodically.
func (s *shareTokenStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for tok, e := range s.tokens {
		if now.After(e.expiry) {
			delete(s.tokens, tok)
		}
	}
}

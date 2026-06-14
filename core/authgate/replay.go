package authgate

import (
	"sync"
	"time"
)

// ReplayCache remembers recently-seen nonces so a captured AUTH token cannot be
// replayed within its validity window. Safe for concurrent use.
//
// Eviction is O(n) per call, which is fine at phase-1 scale (a nonce lives for
// ttl; at ~50 handshakes/s and a 60s ttl that is a few thousand entries). A
// bucketed/expiry-heap variant is a later optimization if profiling demands it.
type ReplayCache struct {
	ttl  time.Duration
	now  func() time.Time
	mu   sync.Mutex
	seen map[[16]byte]time.Time
}

// NewReplayCache returns a cache that remembers nonces for ttl.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{ttl: ttl, now: time.Now, seen: make(map[[16]byte]time.Time)}
}

// Seen records nonce and reports whether it had already been seen within ttl. A
// return of true means the token is a replay and must be rejected.
func (c *ReplayCache) Seen(nonce [16]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.evictLocked(now)
	if ts, ok := c.seen[nonce]; ok && now.Sub(ts) <= c.ttl {
		return true
	}
	c.seen[nonce] = now
	return false
}

func (c *ReplayCache) evictLocked(now time.Time) {
	for k, ts := range c.seen {
		if now.Sub(ts) > c.ttl {
			delete(c.seen, k)
		}
	}
}

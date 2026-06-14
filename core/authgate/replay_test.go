package authgate

import (
	"sync"
	"testing"
	"time"
)

func TestReplayCacheDetectsReplay(t *testing.T) {
	c := NewReplayCache(time.Minute)
	var n [16]byte
	n[0] = 42
	if c.Seen(n) {
		t.Fatal("first Seen = true, want false")
	}
	if !c.Seen(n) {
		t.Fatal("second Seen = false, want true (replay)")
	}
}

func TestReplayCacheEvictsAfterTTL(t *testing.T) {
	c := NewReplayCache(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	var n [16]byte
	n[0] = 7
	c.Seen(n) // record at base
	c.now = func() time.Time { return base.Add(2 * time.Minute) } // past ttl
	if c.Seen(n) {
		t.Fatal("Seen after eviction = true, want false")
	}
}

func TestReplayCacheConcurrent(t *testing.T) {
	c := NewReplayCache(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var n [16]byte
			n[0] = byte(i)
			c.Seen(n)
		}(i)
	}
	wg.Wait()
}

package session

import (
	"testing"
	"time"
)

// seqReader is a deterministic io.Reader for tests: it fills bytes with an
// incrementing pattern, so minted SessionIDs/tokens are non-zero and distinct.
type seqReader struct{ b byte }

func (r *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func TestManagerCreateAndResume(t *testing.T) {
	m := NewManager(time.Minute)
	m.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	m.rand = &seqReader{}
	dev := [16]byte{0xAA}

	s, err := m.create(dev)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.SessionID == zeroSessionID {
		t.Fatal("minted SessionID is the zero sentinel")
	}
	if s.DeviceID != dev {
		t.Fatalf("DeviceID = %x, want %x", s.DeviceID, dev)
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1", m.Count())
	}

	got, err := m.resume(dev, s.SessionID, s.ResumeToken)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got != s {
		t.Fatal("resume returned a different *Session; want the same instance")
	}
}

func TestManagerResumeWrongToken(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{1}
	s, _ := m.create(dev)
	bad := s.ResumeToken
	bad[0] ^= 0xFF
	if _, err := m.resume(dev, s.SessionID, bad); err == nil {
		t.Fatal("resume with wrong token: want error")
	}
}

func TestManagerResumeWrongDevice(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	s, _ := m.create([16]byte{1})
	if _, err := m.resume([16]byte{2}, s.SessionID, s.ResumeToken); err == nil {
		t.Fatal("resume with wrong device: want error")
	}
}

func TestManagerResumeUnknown(t *testing.T) {
	m := NewManager(time.Minute)
	if _, err := m.resume([16]byte{1}, [16]byte{9}, [32]byte{}); err == nil {
		t.Fatal("resume unknown session: want error")
	}
}

func TestManagerResumeExpired(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	base := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return base }
	dev := [16]byte{1}
	s, _ := m.create(dev)
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := m.resume(dev, s.SessionID, s.ResumeToken); err == nil {
		t.Fatal("resume expired session: want error")
	}
}

func TestManagerSweepEvictsExpired(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	base := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return base }
	m.create([16]byte{1})
	m.create([16]byte{2})
	if m.Count() != 2 {
		t.Fatalf("Count = %d, want 2", m.Count())
	}
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	m.Sweep()
	if m.Count() != 0 {
		t.Fatalf("Count after sweep = %d, want 0", m.Count())
	}
}

package session

import (
	"net"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

func TestBindCreatesNewSession(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}

	client, server := net.Pipe()
	defer client.Close()

	type res struct {
		sid [16]byte
		tok [32]byte
		err error
	}
	cdone := make(chan res, 1)
	go func() {
		// New-session request: zero SessionID.
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(zeroSessionID, [32]byte{}))
		typ, payload, err := frame.ReadFrame(client)
		if err != nil || typ != frame.TypeSessionBind {
			cdone <- res{err: err}
			return
		}
		sid, tok, _ := parseBind(payload)
		cdone <- res{sid: sid, tok: tok}
	}()

	s, err := m.Bind(dev, server)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	c := <-cdone
	if c.err != nil {
		t.Fatalf("client: %v", c.err)
	}
	if s.DeviceID != dev {
		t.Fatalf("session DeviceID = %x, want %x", s.DeviceID, dev)
	}
	if c.sid != s.SessionID || c.tok != s.ResumeToken {
		t.Fatal("client-received SessionID/token != server session")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1", m.Count())
	}
}

func TestBindResumesExistingSession(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}
	orig, _ := m.create(dev)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(orig.SessionID, orig.ResumeToken))
		frame.ReadFrame(client) // drain ack
	}()

	s, err := m.Bind(dev, server)
	if err != nil {
		t.Fatalf("Bind resume: %v", err)
	}
	if s.SessionID != orig.SessionID {
		t.Fatal("resume returned a different SessionID")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1 (no new session on resume)", m.Count())
	}
}

func TestBindRejectsNonBindFrame(t *testing.T) {
	m := NewManager(time.Minute)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeData, []byte("x"))
		client.Close()
	}()
	if _, err := m.Bind([16]byte{1}, server); err == nil {
		t.Fatal("Bind on a DATA frame: want error, got nil")
	}
}

func TestBindRejectsBadResume(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}
	orig, _ := m.create(dev)
	bad := orig.ResumeToken
	bad[0] ^= 0xFF

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(orig.SessionID, bad))
		client.Close()
	}()
	if _, err := m.Bind(dev, server); err == nil {
		t.Fatal("Bind with bad resume token: want error, got nil")
	}
}

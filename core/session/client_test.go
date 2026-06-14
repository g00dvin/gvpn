package session

import (
	"net"
	"testing"
	"time"
)

// serveBind accepts connections and runs Manager.Bind for deviceID on each,
// closing the connection afterward. Returns the listener (close it to stop).
func serveBind(t *testing.T, m *Manager, deviceID [16]byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				m.Bind(deviceID, c) // ack is written before we close
			}(c)
		}
	}()
	return ln
}

func TestClientBindNewThenResume(t *testing.T) {
	m := NewManager(time.Minute)
	dev := [16]byte{0x42}
	ln := serveBind(t, m, dev)
	defer ln.Close()

	// First connect: brand-new session (zero SessionID).
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	sid, tok, err := ClientBind(c1, zsid, ztok)
	c1.Close()
	if err != nil {
		t.Fatalf("ClientBind new: %v", err)
	}
	if sid == zsid {
		t.Fatal("assigned SessionID is the zero sentinel")
	}

	// Reconnect: resume with the stored SessionID + token.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	sid2, tok2, err := ClientBind(c2, sid, tok)
	c2.Close()
	if err != nil {
		t.Fatalf("ClientBind resume: %v", err)
	}
	if sid2 != sid || tok2 != tok {
		t.Fatal("resume returned a different SessionID/token")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1 (resume must not mint a new session)", m.Count())
	}
}

func TestClientResumeWrongTokenFails(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{1}
	orig, _ := m.create(dev)
	ln := serveBind(t, m, dev)
	defer ln.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	bad := orig.ResumeToken
	bad[0] ^= 0xFF
	// Server's Bind fails and closes without an ack, so the client's read errors.
	if _, _, err := ClientBind(c, orig.SessionID, bad); err == nil {
		t.Fatal("ClientBind with wrong token: want error, got nil")
	}
}

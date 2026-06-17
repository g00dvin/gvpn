package authgate

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

// fakeDecoy records that it was called and the prefix it received.
type fakeDecoy struct {
	mu     sync.Mutex
	called bool
	prefix []byte
}

func (f *fakeDecoy) Handle(client net.Conn, prefix []byte) error {
	f.mu.Lock()
	f.called = true
	f.prefix = append([]byte(nil), prefix...)
	f.mu.Unlock()
	client.Close()
	return nil
}

func TestGateAuthenticatedPath(t *testing.T) {
	dev := [16]byte{1, 2, 3, 4}
	psk := []byte("device-psk")
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), nil)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, dev, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		frame.WriteFrame(client, frame.TypeData, []byte("packet"))
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Authenticated || res.DeviceID != dev {
		t.Fatalf("auth=%v dev=%x, want true %x", res.Authenticated, res.DeviceID, dev)
	}
	// The gate must consume only the AUTH frame; the DATA frame follows.
	typ, payload, err := frame.ReadFrame(res.Conn)
	if err != nil {
		t.Fatalf("ReadFrame after auth: %v", err)
	}
	if typ != frame.TypeData || string(payload) != "packet" {
		t.Fatalf("next frame = (%d,%q), want (DATA,%q)", typ, payload, "packet")
	}
	res.Conn.Close()
}

func TestGateDecoyOnHTTP(t *testing.T) {
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd)

	client, server := net.Pipe()
	defer client.Close()
	sent := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() {
		client.Write(sent)
		client.Close()
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Authenticated {
		t.Fatal("HTTP request authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for HTTP request")
	}
	if len(fd.prefix) == 0 || !bytes.HasPrefix(sent, fd.prefix) {
		t.Fatalf("decoy prefix %q must be a leading slice of the client bytes", fd.prefix)
	}
}

func TestGateDecoyOnUnknownDevice(t *testing.T) {
	dev := [16]byte{2}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd) // device not registered
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, dev, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()

	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("unknown device authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for unknown device")
	}
}

func TestGateRejectsReplay(t *testing.T) {
	dev := [16]byte{5}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), fd)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	tok, _ := MakeToken(psk, dev, time.Unix(now, 0))

	// First use authenticates.
	c1, s1 := net.Pipe()
	go func() { frame.WriteFrame(c1, frame.TypeAuth, tok) }()
	res1, _ := g.Handle(s1)
	if !res1.Authenticated {
		t.Fatal("first use not authenticated")
	}
	c1.Close()
	res1.Conn.Close()

	// Same token again must fall to decoy.
	c2, s2 := net.Pipe()
	defer c2.Close()
	go func() {
		frame.WriteFrame(c2, frame.TypeAuth, tok)
		c2.Close()
	}()
	res2, _ := g.Handle(s2)
	if res2.Authenticated {
		t.Fatal("replayed token authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked on replay")
	}
}

func TestGateNilDecoyClosesConn(t *testing.T) {
	g := NewGate(NewMapStore(nil), nil)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		client.Write([]byte("garbage-bytes-not-a-frame"))
		client.Close()
	}()
	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Authenticated {
		t.Fatal("garbage authenticated; want decoy/close")
	}
	// server should now be closed by the gate: a write must fail.
	if _, err := server.Write([]byte("x")); err == nil {
		t.Fatal("server conn still open after nil-decoy decoy path")
	}
}

func TestGateEnrollPath(t *testing.T) {
	uid := [16]byte{4, 5, 6}
	psk := []byte("enroll-psk")
	g := NewGate(NewMapStoreWithEnroll(nil, map[[16]byte][]byte{uid: psk}), nil)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeEnrollToken(psk, uid, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		frame.WriteFrame(client, frame.TypeData, []byte("after"))
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Authenticated || res.Kind != KindEnroll || res.UserID != uid {
		t.Fatalf("auth=%v kind=%d user=%x; want true enroll %x", res.Authenticated, res.Kind, res.UserID, uid)
	}
	if res.DeviceID != ([16]byte{}) {
		t.Fatal("DeviceID must be zero on the enroll path")
	}
	typ, payload, err := frame.ReadFrame(res.Conn)
	if err != nil || typ != frame.TypeData || string(payload) != "after" {
		t.Fatalf("next frame = (%d,%q),%v; want (DATA,after)", typ, payload, err)
	}
	res.Conn.Close()
}

func TestGateDecoyOnUnknownEnrollUser(t *testing.T) {
	uid := [16]byte{1, 1}
	psk := []byte("enroll-psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd) // no enroll users
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeEnrollToken(psk, uid, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()
	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("unknown enroll user authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for unknown enroll user")
	}
}

func TestGateDeviceTokenNotAcceptedAsEnrollOnlyID(t *testing.T) {
	// An id present only in the enroll map must NOT authenticate a KindDevice
	// token: the device lookup misses, so the connection goes to the decoy.
	id := [16]byte{2, 2}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStoreWithEnroll(nil, map[[16]byte][]byte{id: psk}), fd)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, id, time.Unix(now, 0)) // DEVICE token
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()
	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("device token matched an enroll-only id; want decoy")
	}
}

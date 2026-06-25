package goste2e

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/session"
)

// TestGOSTControlHandshake runs the gvpn client<->server control handshake over
// a real loopback GOST-TLS connection: a GOST-TLS handshake (both ends via the
// engine), then the AUTH gate and SESSION_BIND exchange. Cross-compiled for
// android/amd64 and run on the emulator, it proves the engine negotiates real
// GOST TLS and the framed control protocol works on the Android ABI.
//
// With GVPN_REQUIRE_GOST=1 a missing engine is fatal (not skipped) so CI / the
// emulator cannot false-green.
func TestGOSTControlHandshake(t *testing.T) {
	if err := gosttls.Init(); err != nil {
		if os.Getenv("GVPN_REQUIRE_GOST") == "1" {
			t.Fatalf("gost engine required but unavailable: %v", err)
		}
		t.Skipf("gost engine unavailable: %v", err)
	}

	// CLI-free GOST cert: the server presents it, the client pins it as CA.
	dir := t.TempDir()
	cert := filepath.Join(dir, "e2e.crt")
	key := filepath.Join(dir, "e2e.key")
	if err := gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	// Shared device identity for the AUTH gate.
	var deviceID [16]byte
	copy(deviceID[:], "gvpn-e2e-device!") // exactly 16 bytes
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatalf("rand psk: %v", err)
	}
	store := authgate.NewMapStore(map[[16]byte][]byte{deviceID: psk})
	gate := authgate.NewGate(store, nil) // nil decoy: the success path never invokes it
	mgr := session.NewManager(time.Minute)

	ln, err := gosttls.Listen("tcp", "127.0.0.1:0", gosttls.Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	type serverObs struct {
		res authgate.Result
		sid [16]byte
		err error
	}
	var obs serverObs
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			obs.err = err
			return
		}
		defer conn.Close()
		res, err := gate.Handle(conn)
		if err != nil {
			obs.err = err
			return
		}
		obs.res = res
		sess, err := mgr.Bind(res.DeviceID, conn)
		if err != nil {
			obs.err = err
			return
		}
		obs.sid = sess.SessionID
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cc, err := gosttls.Dial(ctx, "tcp", ln.Addr().String(),
		gosttls.Config{CAFile: cert, ServerName: "e2e.gvpn"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()

	if err := authgate.WriteAuth(cc, psk, deviceID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zeroSID [16]byte
	var zeroTok [32]byte
	newSID, _, err := session.ClientBind(cc, zeroSID, zeroTok)
	if err != nil {
		t.Fatalf("ClientBind: %v", err)
	}

	wg.Wait()
	if obs.err != nil {
		t.Fatalf("server: %v", obs.err)
	}

	// A real GOST suite was negotiated (not a fallback).
	if name := gosttls.CipherName(cc); !strings.Contains(name, "GOST") {
		t.Fatalf("negotiated cipher %q does not contain GOST", name)
	}
	// The AUTH gate verified the right device.
	if !obs.res.Authenticated || obs.res.Kind != authgate.KindDevice {
		t.Fatalf("gate result: authenticated=%v kind=%d", obs.res.Authenticated, obs.res.Kind)
	}
	if obs.res.DeviceID != deviceID {
		t.Fatalf("gate deviceID = %x, want %x", obs.res.DeviceID, deviceID)
	}
	// SESSION_BIND minted a non-zero session, agreed on both ends.
	if newSID == zeroSID {
		t.Fatalf("client session id is zero")
	}
	if obs.sid != newSID {
		t.Fatalf("session id mismatch: server %x client %x", obs.sid, newSID)
	}
}

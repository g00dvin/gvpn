package mobile

import (
	"sync"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/wgengine"
)

// recordingReporter captures the state/error callbacks for assertions.
type recordingReporter struct {
	mu     sync.Mutex
	states []string
	errors []string
}

func (r *recordingReporter) OnState(s string) {
	r.mu.Lock()
	r.states = append(r.states, s)
	r.mu.Unlock()
}
func (r *recordingReporter) OnError(m string) {
	r.mu.Lock()
	r.errors = append(r.errors, m)
	r.mu.Unlock()
}
func (r *recordingReporter) stateList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}
func (r *recordingReporter) errorCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.errors)
}

func testBundleJSON(t *testing.T, serverPub wgengine.Key, tunnelIP string) string {
	t.Helper()
	b, _, err := provision.Generate("u", tunnelIP, provision.GenerateParams{
		ServerWGPublicKey: serverPub, ServerEndpoint: "127.0.0.1:443", ServerName: "vpn",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

func TestParseBundleValid(t *testing.T) {
	srv, _ := wgengine.GeneratePrivateKey()
	cc, err := parseBundle(testBundleJSON(t, srv.PublicKey(), "10.100.0.2"))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if cc.endpoint != "127.0.0.1:443" || cc.serverName != "vpn" || len(cc.authPSK) == 0 {
		t.Fatalf("parsed config = %+v", cc)
	}
	if cc.serverPub != srv.PublicKey() {
		t.Fatal("server pub key mismatch")
	}
}

func TestParseBundleRejectsBadInput(t *testing.T) {
	if _, err := parseBundle("not json"); err == nil {
		t.Fatal("parseBundle(bad json): want error")
	}
	if _, err := parseBundle(`{"device_id":"zz","auth_psk":"00"}`); err == nil {
		t.Fatal("parseBundle(bad device id): want error")
	}
}

func TestConnectReportsConnectingThenErrorsOnBadBundle(t *testing.T) {
	rep := &recordingReporter{}
	if _, err := Connect("not json", -1, rep); err == nil {
		t.Fatal("Connect(bad bundle): want error")
	}
	states := rep.stateList()
	if len(states) == 0 || states[0] != "connecting" {
		t.Fatalf("states = %v, want first = connecting", states)
	}
	if rep.errorCount() == 0 {
		t.Fatal("Connect failure must report an error")
	}
}

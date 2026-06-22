package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newAdminFixture(t *testing.T) (*adminServer, *provision.FileStore) {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatal(err)
	}
	srvWG, _ := provision.ParseKey(strings.Repeat("22", 32))
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		server.Config{WGPrivateKey: srvWG}, tunDev)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	as := newAdminServer(srv, store, newShareTokenStore(time.Hour), enrollCoords{Host: "vpn:443", SNI: "vpn"})
	return as, store
}

func TestAdminDashboardLists(t *testing.T) {
	as, store := newAdminFixture(t)
	if _, _, err := store.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	as.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard code = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "alice") {
		t.Fatalf("dashboard does not list the user: %s", w.Body.String())
	}
}

func TestAdminAddUserShowsEnrollLink(t *testing.T) {
	as, store := newAdminFixture(t)
	form := url.Values{"handle": {"bob"}}
	r := httptest.NewRequest("POST", "/users/add", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	as.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("add user code = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "gvpn://enroll?") {
		t.Fatalf("add user response missing enroll link: %s", w.Body.String())
	}
	if _, ok := store.User("bob"); !ok {
		t.Fatal("user bob was not created")
	}
}

func TestAdminToggleEnrollAndCap(t *testing.T) {
	as, store := newAdminFixture(t)
	if _, _, err := store.AddUser("carol"); err != nil {
		t.Fatal(err)
	}
	post := func(path string, form url.Values) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		as.ServeHTTP(w, r)
		return w.Code
	}
	if code := post("/users/enroll", url.Values{"handle": {"carol"}, "open": {"false"}}); code != http.StatusSeeOther {
		t.Fatalf("toggle enroll code = %d, want 303", code)
	}
	if code := post("/users/cap", url.Values{"handle": {"carol"}, "cap": {"3"}}); code != http.StatusSeeOther {
		t.Fatalf("set cap code = %d, want 303", code)
	}
	u, _ := store.User("carol")
	if u.EnrollOpen || u.DeviceCap != 3 {
		t.Fatalf("user = %+v, want EnrollOpen=false cap=3", u)
	}
}

func TestAdminMintShareLink(t *testing.T) {
	as, store := newAdminFixture(t)
	if _, _, err := store.AddUser("dan"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"handle": {"dan"}}
	r := httptest.NewRequest("POST", "/share/mint", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	as.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/enroll/") {
		t.Fatalf("mint share code=%d body=%s", w.Code, w.Body.String())
	}
}

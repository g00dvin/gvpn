package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/provision"
)

func TestSharePageRendersForValidToken(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	tokens := newShareTokenStore(time.Hour)
	tok, _ := tokens.Mint("alice")

	sh := newShareServer(store, tokens, enrollCoords{Host: "vpn:443", SNI: "vpn"})
	r := httptest.NewRequest("GET", "/enroll/"+tok, nil)
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("share code = %d, body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "gvpn://enroll?") {
		t.Fatalf("share page missing deep link: %s", body)
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("share page missing embedded QR: %s", body)
	}
}

func TestSharePageRejectsUnknownToken(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, _ := provision.NewFileStore(reg, c)
	sh := newShareServer(store, newShareTokenStore(time.Hour), enrollCoords{Host: "vpn:443", SNI: "vpn"})
	r := httptest.NewRequest("GET", "/enroll/nope", nil)
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown token code = %d, want 404", w.Code)
	}
}

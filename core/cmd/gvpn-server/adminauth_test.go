package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBasicAuthGuard(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.DefaultCost)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	guarded := basicAuth(string(hash), inner)

	// No credentials -> 401.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no creds: code = %d, want 401", w.Code)
	}

	// Wrong password -> 401.
	r = httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "wrong")
	w = httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pw: code = %d, want 401", w.Code)
	}

	// Correct password -> 200.
	r = httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("admin", "s3cret")
	w = httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("correct pw: code = %d, want 200", w.Code)
	}
}

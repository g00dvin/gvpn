package main

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// basicAuth wraps h with HTTP Basic Auth verifying the request password against
// the bcrypt passwordHash. The username is ignored (the admin console is a
// single-operator, localhost-only surface). A missing or wrong password yields
// 401 with a WWW-Authenticate challenge.
func basicAuth(passwordHash string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="gvpn-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

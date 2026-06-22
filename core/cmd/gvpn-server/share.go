package main

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"

	"github.com/g00dvin/gvpn/core/provision"
)

// shareServer serves the public, phone-facing enrollment page over standard TLS.
// GET /enroll/<token> resolves an opaque share token to a user and renders the
// gvpn://enroll deep link plus a QR image; the token (not the PSK) is in the URL.
type shareServer struct {
	store  *provision.FileStore
	tokens *shareTokenStore
	coords enrollCoords
}

func newShareServer(store *provision.FileStore, tokens *shareTokenStore, coords enrollCoords) *shareServer {
	return &shareServer{store: store, tokens: tokens, coords: coords}
}

func (s *shareServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.URL.Path, "/enroll/")
	if !ok || tok == "" {
		http.NotFound(w, r)
		return
	}
	handle, ok := s.tokens.Resolve(tok)
	if !ok {
		http.NotFound(w, r)
		return
	}
	u, ok := s.store.User(handle)
	if !ok {
		http.NotFound(w, r)
		return
	}
	uid, err := provision.ParseDeviceID(u.ID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	psk, ok := s.store.EnrollPSK(uid)
	if !ok {
		http.NotFound(w, r)
		return
	}
	uri := provision.EnrollLink{
		User: handle, EnrollPSK: psk, Host: s.coords.Host, ServerName: s.coords.SNI, CertFP: s.coords.CAFp,
	}.URI()
	png, err := provision.QRPNG(uri, 320)
	if err != nil {
		http.Error(w, "qr error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page body embeds the live enrollment PSK (inside the gvpn:// URI), so
	// keep it out of browser/intermediary caches.
	w.Header().Set("Cache-Control", "no-store, private")
	// HREF is template.URL because html/template's href sanitizer otherwise
	// rewrites the non-allowlisted gvpn:// scheme to "#ZgotmplZ". This is safe:
	// EnrollLink.URI() builds the URL with url.Values.Encode, so every component
	// (including the user handle) is percent-encoded and cannot break out of the
	// attribute. The visible link text uses the plain (auto-escaped) string.
	_ = shareTmpl.Execute(w, struct {
		Handle string
		URI    string
		HREF   template.URL
		QR     string
	}{handle, uri, template.URL(uri), base64.StdEncoding.EncodeToString(png)})
}

var shareTmpl = template.Must(template.New("sharepage").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Enroll {{.Handle}}</title></head><body>
<h1>Enroll this device</h1>
<p>Scan with the gvpn app, or tap the link:</p>
<p><img alt="enroll QR" src="data:image/png;base64,{{.QR}}"></p>
<p><a href="{{.HREF}}">{{.URI}}</a></p>
</body></html>`))

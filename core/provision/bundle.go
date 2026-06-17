package provision

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

// EnrollLink is the data carried by an enrollment bundle: the user-level
// credential plus how to reach the server. It is rendered as a gvpn://enroll URI.
type EnrollLink struct {
	User       string
	EnrollPSK  []byte
	Host       string // host:port
	ServerName string // TLS SNI
	CertFP     string // optional base64/hex GOST cert fingerprint to pin
}

// URI renders the canonical gvpn://enroll?... deep link.
func (l EnrollLink) URI() string {
	q := url.Values{}
	q.Set("u", l.User)
	q.Set("psk", base64.RawURLEncoding.EncodeToString(l.EnrollPSK))
	q.Set("h", l.Host)
	q.Set("sni", l.ServerName)
	if l.CertFP != "" {
		q.Set("caf", l.CertFP)
	}
	return "gvpn://enroll?" + q.Encode()
}

// ParseEnrollURI parses a gvpn://enroll?... deep link.
func ParseEnrollURI(s string) (EnrollLink, error) {
	u, err := url.Parse(s)
	if err != nil {
		return EnrollLink{}, fmt.Errorf("provision: parse enroll uri: %w", err)
	}
	if u.Scheme != "gvpn" || u.Host != "enroll" {
		return EnrollLink{}, fmt.Errorf("provision: not a gvpn://enroll uri: %q", s)
	}
	q := u.Query()
	psk, err := base64.RawURLEncoding.DecodeString(q.Get("psk"))
	if err != nil {
		return EnrollLink{}, fmt.Errorf("provision: enroll psk: %w", err)
	}
	return EnrollLink{
		User: q.Get("u"), EnrollPSK: psk, Host: q.Get("h"),
		ServerName: q.Get("sni"), CertFP: q.Get("caf"),
	}, nil
}

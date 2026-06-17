package provision

import "testing"

func TestEnrollURIRoundTrip(t *testing.T) {
	in := EnrollLink{
		User: "alice", EnrollPSK: []byte("0123456789abcdef0123456789abcdef"),
		Host: "vpn.example.com:443", ServerName: "vpn.example.com", CertFP: "sha256fp",
	}
	uri := in.URI()
	if uri[:14] != "gvpn://enroll?" {
		t.Fatalf("uri prefix = %q", uri[:14])
	}
	out, err := ParseEnrollURI(uri)
	if err != nil {
		t.Fatalf("ParseEnrollURI: %v", err)
	}
	if out.User != in.User || out.Host != in.Host || out.ServerName != in.ServerName ||
		out.CertFP != in.CertFP || string(out.EnrollPSK) != string(in.EnrollPSK) {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestParseEnrollURIRejectsNonGvpn(t *testing.T) {
	if _, err := ParseEnrollURI("https://example.com/enroll"); err == nil {
		t.Fatal("expected scheme error")
	}
}

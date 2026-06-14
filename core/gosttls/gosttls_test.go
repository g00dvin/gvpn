package gosttls

import (
	"strings"
	"testing"
)

func TestInitAndVersion(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := Init(); err != nil { // must be idempotent
		t.Fatalf("Init (2nd call): %v", err)
	}
	if v := Version(); !strings.HasPrefix(v, "OpenSSL 3.") {
		t.Fatalf("Version = %q, want OpenSSL 3.x", v)
	}
}

package mobile

import "testing"

func TestVersionNonEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() returned empty string")
	}
}

package main

import (
	"reflect"
	"testing"
)

func TestMasqueradeArgs(t *testing.T) {
	add := masqueradeArgs("-A", "10.100.0.0/24")
	wantAdd := []string{"-t", "nat", "-A", "POSTROUTING", "-s", "10.100.0.0/24", "-j", "MASQUERADE"}
	if !reflect.DeepEqual(add, wantAdd) {
		t.Fatalf("add args = %v, want %v", add, wantAdd)
	}
	del := masqueradeArgs("-D", "10.100.0.0/24")
	if del[2] != "-D" {
		t.Fatalf("delete args use %q, want -D", del[2])
	}
}

// recordingNAT is the stub used by serve_test.go; assert it satisfies NAT here.
func TestRecordingNATImplementsNAT(t *testing.T) {
	var _ NAT = (*recordingNAT)(nil)
}

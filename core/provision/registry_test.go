package provision

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrySaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	reg := Registry{
		Users: []User{{
			Handle: "alice", ID: "11111111-1111-4111-8111-111111111111",
			EnrollPSKEnc: "enc", DeviceCap: 5, EnrollOpen: true, CreatedAt: time.Unix(1, 0).UTC(),
		}},
		Devices: []Device{{
			DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
			WGPublic: "aa", TunnelIP: "10.100.0.2", AuthPSKEnc: "enc2",
			CreatedAt: time.Unix(2, 0).UTC(), Source: "admin",
		}},
	}
	if err := SaveRegistry(path, reg); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	got, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].Handle != "alice" {
		t.Fatalf("users = %+v", got.Users)
	}
	if len(got.Devices) != 1 || got.Devices[0].TunnelIP != "10.100.0.2" {
		t.Fatalf("devices = %+v", got.Devices)
	}
}

func TestLoadRegistryMissingIsEmpty(t *testing.T) {
	got, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadRegistry missing: %v", err)
	}
	if len(got.Users) != 0 || len(got.Devices) != 0 {
		t.Fatal("missing file should yield an empty registry")
	}
}

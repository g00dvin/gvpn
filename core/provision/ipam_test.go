package provision

import (
	"net/netip"
	"testing"
)

func TestAllocateIPFirstIsDotTwo(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/24")
	got, err := AllocateIP(nil, subnet)
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	if got != netip.MustParseAddr("10.100.0.2") {
		t.Fatalf("first alloc = %v, want 10.100.0.2 (.0 network, .1 server reserved)", got)
	}
}

func TestAllocateIPSkipsUsed(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/24")
	used := []netip.Addr{
		netip.MustParseAddr("10.100.0.2"),
		netip.MustParseAddr("10.100.0.3"),
	}
	got, err := AllocateIP(used, subnet)
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	if got != netip.MustParseAddr("10.100.0.4") {
		t.Fatalf("alloc = %v, want 10.100.0.4", got)
	}
}

func TestAllocateIPExhausted(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/30") // hosts: .1 (reserved), .2 usable, .3 broadcast
	used := []netip.Addr{netip.MustParseAddr("10.100.0.2")}
	if _, err := AllocateIP(used, subnet); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

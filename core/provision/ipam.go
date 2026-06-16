package provision

import (
	"errors"
	"net/netip"
)

// AllocateIP returns the lowest free host in subnet that is not in used. It
// reserves the network address and the first host (.1, the server TUN), and for
// IPv4 it skips the broadcast address. Allocation starts at the second host.
func AllocateIP(used []netip.Addr, subnet netip.Prefix) (netip.Addr, error) {
	subnet = subnet.Masked()
	taken := make(map[netip.Addr]bool, len(used))
	for _, a := range used {
		taken[a] = true
	}
	bcast := broadcast(subnet)
	// First host = network+1 (reserved for the server); start candidates at +2.
	addr := subnet.Addr().Next() // .1 (reserved)
	addr = addr.Next()           // .2 (first allocatable)
	for subnet.Contains(addr) {
		if subnet.Addr().Is4() && addr == bcast {
			break
		}
		if !taken[addr] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, errors.New("provision: subnet exhausted")
}

// broadcast returns the all-ones host address of an IPv4 prefix (zero value for IPv6).
func broadcast(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	b := p.Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		byteIdx := 3 - i/8
		b[byteIdx] |= 1 << (uint(i) % 8)
	}
	return netip.AddrFrom4(b)
}

package main

import (
	"fmt"
	"os/exec"
	"sync"
)

// NAT installs and removes the source-NAT rule that lets tunnel clients reach
// the internet through the server.
type NAT interface {
	Enable(subnet string) error
	Disable(subnet string) error
}

// masqueradeArgs builds the iptables argv for the single POSTROUTING MASQUERADE
// rule over subnet. op is "-A" (add) or "-D" (delete).
func masqueradeArgs(op, subnet string) []string {
	return []string{"-t", "nat", op, "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}
}

// iptablesNAT is the production NAT, shelling out to iptables.
type iptablesNAT struct{}

func (iptablesNAT) Enable(subnet string) error  { return runIptables(masqueradeArgs("-A", subnet)) }
func (iptablesNAT) Disable(subnet string) error { return runIptables(masqueradeArgs("-D", subnet)) }

func runIptables(args []string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("gvpn-server: iptables %v: %w: %s", args, err, out)
	}
	return nil
}

// recordingNAT is a test double that records the subnets it was asked to enable
// and disable without touching the kernel. It is mutex-guarded because Enable/
// Disable run on the server goroutine while the test reads via the accessors.
type recordingNAT struct {
	mu       sync.Mutex
	enabled  []string
	disabled []string
}

func (n *recordingNAT) Enable(subnet string) error {
	n.mu.Lock()
	n.enabled = append(n.enabled, subnet)
	n.mu.Unlock()
	return nil
}

func (n *recordingNAT) Disable(subnet string) error {
	n.mu.Lock()
	n.disabled = append(n.disabled, subnet)
	n.mu.Unlock()
	return nil
}

func (n *recordingNAT) enabledSubnets() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.enabled...)
}

func (n *recordingNAT) disabledSubnets() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.disabled...)
}

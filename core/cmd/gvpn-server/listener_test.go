package main

import (
	"net"
	"testing"

	"github.com/g00dvin/gvpn/core/gosttls"
)

// TestGostListenerSatisfiesNetListener is a compile-time + structural assertion
// that the adapter turns a *gosttls.Listener into a net.Listener.
func TestGostListenerSatisfiesNetListener(t *testing.T) {
	var _ net.Listener = gostNetListener{}
	var l gostNetListener
	if _, ok := interface{}(l.Listener).(*gosttls.Listener); !ok {
		t.Fatal("gostNetListener must embed *gosttls.Listener")
	}
}

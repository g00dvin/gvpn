package wgengine

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestEndToEndTunnelHTTP(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("192.168.4.1")
	clientIP := netip.MustParseAddr("192.168.4.2")

	// netstack TUNs for both ends.
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}

	// Transport pair over a TCP loopback connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type accepted struct {
		c   net.Conn
		err error
	}
	ac := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ac <- accepted{c, err}
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ac
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	serverPT := transport.NewStreamTransport(a.c)
	clientPT := transport.NewStreamTransport(clientConn)

	// Engines. Server waits; client initiates (Endpoint set) with keepalive.
	serverEng, err := New(serverTun, serverPT, Config{
		PrivateKey:    serverPriv,
		PeerPublicKey: clientPriv.PublicKey(),
		AllowedIPs:    []string{clientIP.String() + "/32"},
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	defer serverEng.Close()

	clientEng, err := New(clientTun, clientPT, Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverPriv.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-peer:0", // placeholder; arms client handshake
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer clientEng.Close()

	// HTTP server on the server netstack.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from gvpn wireguard tunnel")
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	// HTTP client over the client netstack; retry while the handshake completes.
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(15 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://192.168.4.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}
	if string(body) != "hello from gvpn wireguard tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (handshake/data path failed)", body)
	}
}

package wgengine

import (
	"fmt"
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

// loopbackPair returns the two ends of a TCP loopback connection.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
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
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ac
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	return a.c, dialed // server side, client side
}

// startClient brings up a single-conn client Engine on its own netstack TUN that
// initiates to the server. It returns the client's netstack (for dialing) and
// the Engine.
func startClient(t *testing.T, clientPriv, serverPub Key, clientIP netip.Addr, clientConn net.Conn) (*netstack.Net, *Engine) {
	t.Helper()
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	eng, err := New(clientTun, transport.NewStreamTransport(clientConn), Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverPub,
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-peer:0",
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	return clientNet, eng
}

// getThrough retries an HTTP GET to the server over the client netstack until
// the handshake completes or the deadline passes.
func getThrough(t *testing.T, clientNet *netstack.Net, serverIP netip.Addr) string {
	t.Helper()
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(fmt.Sprintf("http://%s/", serverIP))
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(body)
	}
	return ""
}

func TestMuxEngineTwoClientsConcurrent(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientAPriv, _ := GeneratePrivateKey()
	clientBPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("10.100.0.1")
	clientAIP := netip.MustParseAddr("10.100.0.2")
	clientBIP := netip.MustParseAddr("10.100.0.3")

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	serverEng, err := NewMuxEngine(serverTun, serverPriv, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("NewMuxEngine: %v", err)
	}
	defer serverEng.Close()
	if err := serverEng.AddPeer(clientAPriv.PublicKey(), clientAIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer A: %v", err)
	}
	if err := serverEng.AddPeer(clientBPriv.PublicKey(), clientBIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer B: %v", err)
	}

	srvSideA, cliSideA := loopbackPair(t)
	srvSideB, cliSideB := loopbackPair(t)
	serverEng.Register(1, transport.NewStreamTransport(srvSideA))
	serverEng.Register(2, transport.NewStreamTransport(srvSideB))

	clientANet, clientAEng := startClient(t, clientAPriv, serverPriv.PublicKey(), clientAIP, cliSideA)
	defer clientAEng.Close()
	clientBNet, clientBEng := startClient(t, clientBPriv, serverPriv.PublicKey(), clientBIP, cliSideB)
	defer clientBEng.Close()

	// HTTP server on the server netstack.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.Host)
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	if got := getThrough(t, clientANet, serverIP); got == "" {
		t.Fatal("client A could not reach the server through the mux tunnel")
	}
	if got := getThrough(t, clientBNet, serverIP); got == "" {
		t.Fatal("client B could not reach the server through the mux tunnel")
	}
}

func TestMuxEngineReconnectResumes(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("10.100.0.1")
	clientIP := netip.MustParseAddr("10.100.0.2")

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	serverEng, err := NewMuxEngine(serverTun, serverPriv, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("NewMuxEngine: %v", err)
	}
	defer serverEng.Close()
	if err := serverEng.AddPeer(clientPriv.PublicKey(), clientIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	// First connection on id 1.
	srvSide1, cliSide1 := loopbackPair(t)
	serverEng.Register(1, transport.NewStreamTransport(srvSide1))
	clientNet1, clientEng1 := startClient(t, clientPriv, serverPriv.PublicKey(), clientIP, cliSide1)
	if got := getThrough(t, clientNet1, serverIP); got != "ok" {
		t.Fatalf("first connect: tunnel body = %q", got)
	}

	// "Reconnect": drop conn 1, register a fresh conn 2 for the same peer.
	clientEng1.Close()
	serverEng.Deregister(1)
	srvSide2, cliSide2 := loopbackPair(t)
	serverEng.Register(2, transport.NewStreamTransport(srvSide2))
	clientNet2, clientEng2 := startClient(t, clientPriv, serverPriv.PublicKey(), clientIP, cliSide2)
	defer clientEng2.Close()

	// The peer (kept across Deregister) resumes on the new connection: the server
	// re-points its endpoint to muxEndpoint{2} on the next valid packet.
	if got := getThrough(t, clientNet2, serverIP); got != "ok" {
		t.Fatalf("after reconnect: tunnel body = %q (endpoint did not re-point)", got)
	}
}

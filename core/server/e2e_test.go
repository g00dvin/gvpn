package server

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestServerEndToEndTunnelHTTP(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("192.168.4.1")
	clientTunIP := netip.MustParseAddr("192.168.4.2")

	// Provision a device and register it where the server's store will load it.
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := store.AddDevice(provision.Device{
		DeviceID: mat.DeviceID, User: mat.User, WGPublic: mat.WGPublic,
		TunnelIP: mat.TunnelIP, Source: "admin",
	}, mat.AuthPSK); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	// The server's per-client TUN factory creates a netstack device and hands the
	// test its *netstack.Net so we can run a service on the server tunnel IP.
	netCh := make(chan *netstack.Net, 1)
	newTun := func() (tun.Device, error) {
		dev, n, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
		if err == nil {
			netCh <- n
		}
		return dev, err
	}

	srv := New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent},
		newTun,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// --- Client side: dial, authenticate, bind a session, start WireGuard. ---
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	psk, _ := hex.DecodeString(bundle.AuthPSK)
	devID, _ := provision.ParseDeviceID(bundle.DeviceID)
	if err := authgate.WriteAuth(conn, psk, devID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		t.Fatalf("ClientBind: %v", err)
	}

	clientPriv, _ := provision.ParseKey(bundle.WGPrivateKey)
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "server:0", // placeholder; arms the client handshake
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	// --- HTTP service on the server's tunnel IP (via the captured netstack). ---
	var serverNet *netstack.Net
	select {
	case serverNet = <-netCh:
	case <-time.After(10 * time.Second):
		t.Fatal("server never created its per-client TUN (auth/bind failed?)")
	}
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello through the gvpn server")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	// --- Client GETs the service over the tunnel; retry while the handshake converges. ---
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(20 * time.Second)
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
	if string(body) != "hello through the gvpn server" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (pipeline/handshake failed)", body)
	}

	_ = context.Background
}

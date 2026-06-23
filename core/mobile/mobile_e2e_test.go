package mobile

import (
	"context"
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
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestMobileTunnelEndToEnd(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	// Registry with one provisioned device.
	reg := filepath.Join(t.TempDir(), "registry.json")
	cph, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, cph)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(), ServerEndpoint: "127.0.0.1:443", ServerName: "vpn",
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

	// Real server over a plain-TCP listener + netstack server TUN.
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := server.New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		server.Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent}, serverTun)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// HTTP service on the server's tunnel IP.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from the mobile tunnel")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	// Client: parse the bundle, build a plain-TCP handshake dialer + netstack TUN,
	// and bring up the tunnel through the mobile package's newTunnel seam.
	data, _ := bundle.Marshal()
	cc, err := parseBundle(string(data))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	plainDial := func(ctx context.Context) (io.ReadWriteCloser, error) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := handshake(conn, cc); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	rep := &recordingReporter{}
	tunnel, err := newTunnel(cc, clientTun, plainDial, rep)
	if err != nil {
		t.Fatalf("newTunnel: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://10.100.0.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}
	if string(body) != "hello from the mobile tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting", body)
	}

	// The reporter saw the connect, and Disconnect is clean + idempotent.
	if states := rep.stateList(); len(states) == 0 || states[len(states)-1] != "connected" {
		t.Fatalf("reporter states = %v, want last = connected", states)
	}
	if err := tunnel.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := tunnel.Disconnect(); err != nil {
		t.Fatalf("second Disconnect: %v", err)
	}
	if states := rep.stateList(); states[len(states)-1] != "disconnected" {
		t.Fatalf("after Disconnect states = %v, want last = disconnected", states)
	}
}

package main

import (
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

func TestRunAssemblesWorkingTunnel(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", strings.Repeat("ab", 32))

	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(), ServerEndpoint: "vpn:443", ServerName: "vpn",
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

	cfg := Config{Registry: reg}
	cfg.WireGuard.PrivateKey = serverWG.Hex()
	cfg.WireGuard.Address = "10.100.0.1/24"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	netCh := make(chan *netstack.Net, 1)
	nat := &recordingNAT{}
	deps := serveDeps{
		Listener: ln,
		NewTUN: func(addrCIDR string) (tun.Device, error) {
			p := netip.MustParsePrefix(addrCIDR)
			dev, n, err := netstack.CreateNetTUN([]netip.Addr{p.Addr()}, nil, 1420)
			if err == nil {
				netCh <- n
			}
			return dev, err
		},
		NAT:      nat,
		LogLevel: device.LogLevelSilent,
	}

	runErr := make(chan error, 1)
	go func() { runErr <- run(cfg, deps) }()
	defer ln.Close()

	var serverNet *netstack.Net
	select {
	case serverNet = <-netCh:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not build the server TUN")
	}

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
		t.Fatalf("client TUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey: clientPriv, PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "server:0", Keepalive: 5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served by gvpn-server")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	hc := &http.Client{Transport: &http.Transport{DialContext: clientNet.DialContext}, Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := hc.Get("http://10.100.0.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}
	if string(body) != "served by gvpn-server" {
		t.Fatalf("tunnel body = %q, want the greeting", body)
	}

	// A working tunnel means run() reached Serve, which is after NAT.Enable.
	if en := nat.enabledSubnets(); len(en) != 1 || en[0] != "10.100.0.0/24" {
		t.Fatalf("NAT enabled = %v, want [10.100.0.0/24]", en)
	}

	ln.Close()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the listener closed")
	}
	if dis := nat.disabledSubnets(); len(dis) != 1 {
		t.Fatalf("NAT disabled = %v, want one teardown", dis)
	}
}

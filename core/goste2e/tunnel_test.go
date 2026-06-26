package goste2e

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// gostNetListener adapts *gosttls.Listener (whose Accept returns *gosttls.Conn,
// itself a net.Conn) to the net.Listener that server.Serve consumes.
type gostNetListener struct{ *gosttls.Listener }

func (l gostNetListener) Accept() (net.Conn, error) { return l.Listener.Accept() }

// TestGOSTTunnelHTTP drives the entire gvpn pipeline over a real loopback
// GOST-TLS transport and pushes real IP traffic through the WireGuard tunnel:
// provision -> server.Server(gosttls listener) <- gosttls.Dial client ->
// AUTH -> SESSION_BIND -> WireGuard -> HTTP GET through the tunnel. Run on the
// emulator it proves IP traffic flows over GOST on the Android ABI.
//
// With GVPN_REQUIRE_GOST=1 a missing engine is fatal (not skipped).
func TestGOSTTunnelHTTP(t *testing.T) {
	if err := gosttls.Init(); err != nil {
		if os.Getenv("GVPN_REQUIRE_GOST") == "1" {
			t.Fatalf("gost engine required but unavailable: %v", err)
		}
		t.Skipf("gost engine unavailable: %v", err)
	}

	// CLI-free GOST cert: the server presents it, the client pins it as CA.
	dir := t.TempDir()
	cert := filepath.Join(dir, "e2e.crt")
	key := filepath.Join(dir, "e2e.key")
	if err := gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	reg := filepath.Join(dir, "registry.json")
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

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := server.New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		server.Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent},
		serverTun,
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	gln, err := gosttls.Listen("tcp", "127.0.0.1:0", gosttls.Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("gosttls.Listen: %v", err)
	}
	ln := gostNetListener{gln}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := gosttls.Dial(ctx, "tcp", ln.Addr().String(),
		gosttls.Config{CAFile: cert, ServerName: "e2e.gvpn"})
	if err != nil {
		t.Fatalf("gosttls.Dial: %v", err)
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
		Endpoint:      "server:0",
		Keepalive:     5,
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
		io.WriteString(w, "hello through gost tunnel")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

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
	if string(body) != "hello through gost tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (pipeline/handshake over GOST failed)", body)
	}
}

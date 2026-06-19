package server

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/enroll"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestServerSelfEnrollEndToEnd connects a brand-new (unprovisioned) device using
// only the user's enroll PSK, completes the in-band enrollment, then tunnels HTTP
// through the freshly granted credentials.
func TestServerSelfEnrollEndToEnd(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")

	reg := filepath.Join(t.TempDir(), "registry.json")
	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// Only a USER exists; no device is pre-provisioned.
	user, enrollPSK, err := store.AddUser("enrollee")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	userID, _ := provision.ParseDeviceID(user.ID)

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		Config{WGPrivateKey: serverWG, Subnet: "10.100.0.0/24", LogLevel: device.LogLevelSilent},
		serverTun,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// --- New device: enroll AUTH -> enroll exchange -> learn credentials. ---
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := authgate.WriteEnrollAuth(conn, enrollPSK, userID); err != nil {
		t.Fatalf("WriteEnrollAuth: %v", err)
	}
	clientPriv, _ := wgengine.GeneratePrivateKey()
	resp, err := enroll.Exchange(conn, [32]byte(clientPriv.PublicKey()))
	if err != nil {
		t.Fatalf("enroll.Exchange: %v", err)
	}
	if resp.TunnelIP != "10.100.0.2" || len(resp.DevicePSK) == 0 {
		t.Fatalf("enroll response = %+v, want tunnel 10.100.0.2 and a psk", resp)
	}

	// Server persisted the new device.
	if _, ok := store.Device(resp.DeviceID); !ok {
		t.Fatal("server did not persist the enrolled device")
	}
	if n := store.DeviceCount("enrollee"); n != 1 {
		t.Fatalf("device count = %d, want 1", n)
	}

	// --- Bring up the tunnel on the same connection using the granted IP. ---
	clientTunIP := netip.MustParseAddr(resp.TunnelIP)
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
		io.WriteString(w, "enrolled and tunneling")
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
		r, err := httpClient.Get("http://10.100.0.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
		break
	}
	if string(body) != "enrolled and tunneling" {
		t.Fatalf("post-enroll tunnel body = %q, want the greeting", body)
	}
}

// TestServerEnrollClosedRejected confirms a user with enrollment closed cannot
// enroll a device (the connection is dropped, no device is created).
func TestServerEnrollClosedRejected(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	user, enrollPSK, err := store.AddUser("closed")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	// Close enrollment for this user by editing the registry directly, then
	// reload the store (there is no CLI/store method to close enrollment yet).
	rgy, _ := provision.LoadRegistry(reg)
	rgy.Users[0].EnrollOpen = false
	if err := provision.SaveRegistry(reg, rgy); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	store, err = provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	userID, _ := provision.ParseDeviceID(user.ID)

	serverTun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	srv, err := New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent}, serverTun)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := authgate.WriteEnrollAuth(conn, enrollPSK, userID); err != nil {
		t.Fatalf("WriteEnrollAuth: %v", err)
	}
	// The gate authenticates (the enroll PSK is valid), but the handler rejects
	// (EnrollOpen=false) and closes the connection before any reply.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("server did not close the connection for a closed-enrollment user")
	}
	if n := store.DeviceCount("closed"); n != 0 {
		t.Fatalf("device count = %d, want 0 (no device created)", n)
	}
}

// Command gvpn-provision manages the gvpn user/device registry: it creates users
// (emitting an enrollment bundle) and admin-provisions devices. It is the
// bootstrap path; while gvpn-server runs, the server owns the registry.
//
// Master key: GVPN_MASTER_KEY (64 hex chars) or --master-key-file.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/g00dvin/gvpn/core/provision"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gvpn-provision:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gvpn-provision <user|device> <add|list|remove|revoke> [flags]")
	}
	group, sub, rest := args[0], args[1], args[2:]
	switch group {
	case "user":
		switch sub {
		case "add":
			return userAdd(rest, out)
		case "list":
			return userList(rest, out)
		case "remove":
			return userRemove(rest, out)
		}
	case "device":
		switch sub {
		case "add":
			return deviceAdd(rest, out)
		case "list":
			return deviceList(rest, out)
		case "revoke":
			return deviceRevoke(rest, out)
		}
	}
	return fmt.Errorf("unknown command %q %q", group, sub)
}

func openStore(registry, masterKeyFile string) (*provision.FileStore, error) {
	key, err := provision.LoadMasterKey(masterKeyFile)
	if err != nil {
		return nil, err
	}
	c, err := provision.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return provision.NewFileStore(registry, c)
}

func userAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	host := fs.String("host", "", "server host:port (required)")
	sni := fs.String("sni", "", "server TLS name (required)")
	caf := fs.String("cert-fp", "", "GOST cert fingerprint to pin (optional)")
	outFile := fs.String("out", "", "write the .gvpn bundle file here (optional)")
	qrFile := fs.String("qr", "", "write a QR PNG here (optional)")
	handleArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		handleArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleArg == "" || *host == "" || *sni == "" {
		return fmt.Errorf("usage: user add <handle> --host <h:port> --sni <name> [--out f] [--qr f]")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	_, enrollPSK, err := store.AddUser(handleArg)
	if err != nil {
		return err
	}
	link := provision.EnrollLink{User: handleArg, EnrollPSK: enrollPSK, Host: *host, ServerName: *sni, CertFP: *caf}
	uri := link.URI()
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(uri+"\n"), 0o600); err != nil {
			return fmt.Errorf("write bundle: %w", err)
		}
	}
	if *qrFile != "" {
		if err := provision.WriteQRPNG(uri, *qrFile, 320); err != nil {
			return fmt.Errorf("write qr: %w", err)
		}
	}
	term, err := provision.TerminalQR(uri)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "created user %q\n%s\n%s\n", handleArg, uri, term)
	if *outFile != "" {
		fmt.Fprintf(out, "bundle: %s\n", *outFile)
	}
	if *qrFile != "" {
		fmt.Fprintf(out, "qr:     %s\n", *qrFile)
	}
	return nil
}

func userList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	reg, err := provision.LoadRegistry(*registry)
	if err != nil {
		return err
	}
	for _, u := range reg.Users {
		fmt.Fprintf(out, "%s  devices=%d cap=%d enroll_open=%v disabled=%v\n",
			u.Handle, store.DeviceCount(u.Handle), u.DeviceCap, u.EnrollOpen, u.Disabled)
	}
	return nil
}

func userRemove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user remove", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	handleArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		handleArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleArg == "" {
		return fmt.Errorf("usage: user remove <handle>")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if err := store.RemoveUser(handleArg); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed user %q (and its devices)\n", handleArg)
	return nil
}

func deviceAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device add", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	user := fs.String("user", "", "owning user handle (required)")
	serverPub := fs.String("server-wg-pubkey", "", "server WG public key hex (required)")
	endpoint := fs.String("endpoint", "", "server endpoint host:port (required)")
	serverName := fs.String("server-name", "", "server TLS name (required)")
	subnet := fs.String("subnet", "10.100.0.0/24", "tunnel subnet for IP allocation")
	caPath := fs.String("ca", "", "server CA PEM path (optional)")
	outFile := fs.String("out", "", "client bundle output file (default <device-id>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" || *serverPub == "" || *endpoint == "" || *serverName == "" {
		return fmt.Errorf("--user, --server-wg-pubkey, --endpoint and --server-name are required")
	}
	pub, err := provision.ParseKey(*serverPub)
	if err != nil {
		return fmt.Errorf("invalid --server-wg-pubkey: %w", err)
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("invalid --subnet: %w", err)
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if _, ok := store.User(*user); !ok {
		return fmt.Errorf("unknown user %q (create it with: user add)", *user)
	}
	used := make([]netip.Addr, 0)
	for _, s := range store.UsedIPs() {
		if a, err := netip.ParseAddr(s); err == nil {
			used = append(used, a)
		}
	}
	ip, err := provision.AllocateIP(used, prefix)
	if err != nil {
		return err
	}
	var caPEM string
	if *caPath != "" {
		raw, err := os.ReadFile(*caPath)
		if err != nil {
			return fmt.Errorf("read --ca: %w", err)
		}
		caPEM = string(raw)
	}
	bundle, mat, err := provision.Generate(*user, ip.String(), provision.GenerateParams{
		ServerWGPublicKey: pub, ServerEndpoint: *endpoint, ServerName: *serverName, ServerCAPEM: caPEM,
	})
	if err != nil {
		return err
	}
	if err := store.AddDevice(provision.Device{
		DeviceID: mat.DeviceID, User: mat.User, WGPublic: mat.WGPublic,
		TunnelIP: mat.TunnelIP, Source: "admin",
	}, mat.AuthPSK); err != nil {
		return err
	}
	dst := *outFile
	if dst == "" {
		dst = mat.DeviceID + ".json"
	}
	data, err := bundle.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	fmt.Fprintf(out, "provisioned device %s for %s\n  tunnel ip: %s\n  bundle:    %s\n",
		mat.DeviceID, *user, ip.String(), dst)
	return nil
}

func deviceList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	user := fs.String("user", "", "filter by user (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, err := provision.LoadRegistry(*registry)
	if err != nil {
		return err
	}
	for _, d := range reg.Devices {
		if *user != "" && d.User != *user {
			continue
		}
		fmt.Fprintf(out, "%s  user=%s ip=%s source=%s\n", d.DeviceID, d.User, d.TunnelIP, d.Source)
	}
	return nil
}

func deviceRevoke(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device revoke", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	idArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		idArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if idArg == "" {
		return fmt.Errorf("usage: device revoke <device-id>")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if err := store.RemoveDevice(idArg); err != nil {
		return err
	}
	fmt.Fprintf(out, "revoked device %s\n", idArg)
	return nil
}

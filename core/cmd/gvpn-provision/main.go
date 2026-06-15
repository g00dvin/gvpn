// Command gvpn-provision mints a gvpn device: it writes a client bundle and
// appends the device to the server registry.
//
// Example:
//
//	gvpn-provision --server-wg-pubkey <hex> --endpoint vpn.example.com:443 \
//	    --server-name vpn.example.com --ca server-ca.pem \
//	    --registry /etc/gvpn/devices.json --out alice.json
package main

import (
	"flag"
	"fmt"
	"io"
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
	fs := flag.NewFlagSet("gvpn-provision", flag.ContinueOnError)
	fs.SetOutput(out)
	serverPub := fs.String("server-wg-pubkey", "", "server WireGuard public key, hex (required)")
	endpoint := fs.String("endpoint", "", "server endpoint host:port (required)")
	serverName := fs.String("server-name", "", "server TLS name (required)")
	caPath := fs.String("ca", "", "path to the server CA certificate PEM (optional)")
	registry := fs.String("registry", "devices.json", "server device registry file to append to")
	outPath := fs.String("out", "", "client bundle output file (default: <device-id>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverPub == "" || *endpoint == "" || *serverName == "" {
		return fmt.Errorf("--server-wg-pubkey, --endpoint and --server-name are required")
	}

	pub, err := provision.ParseKey(*serverPub)
	if err != nil {
		return fmt.Errorf("invalid --server-wg-pubkey: %w", err)
	}
	var caPEM string
	if *caPath != "" {
		raw, err := os.ReadFile(*caPath)
		if err != nil {
			return fmt.Errorf("read --ca: %w", err)
		}
		caPEM = string(raw)
	}

	bundle, device, err := provision.Generate(provision.GenerateParams{
		ServerWGPublicKey: pub,
		ServerEndpoint:    *endpoint,
		ServerName:        *serverName,
		ServerCAPEM:       caPEM,
	})
	if err != nil {
		return err
	}
	if err := provision.AppendDevice(*registry, device); err != nil {
		return err
	}

	dst := *outPath
	if dst == "" {
		dst = device.DeviceID + ".json"
	}
	data, err := bundle.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	fmt.Fprintf(out, "provisioned device %s\n  bundle:   %s\n  registry: %s\n", device.DeviceID, dst, *registry)
	return nil
}

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/g00dvin/gvpn/core/gosttls"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gvpn-server:", err)
		os.Exit(1)
	}
}

// dispatch routes the subcommand.
func dispatch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gvpn-server <serve|gencert> [flags]")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "gencert":
		return cmdGencert(args[1:])
	default:
		return fmt.Errorf("unknown command %q (want serve|gencert)", args[0])
	}
}

// cmdServe loads config and runs the server with the real host seams.
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/gvpn/server.yaml", "path to server.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	ln, err := gosttls.Listen("tcp", cfg.Server.Listen, gosttls.Config{
		CertFile: cfg.TLS.Cert, KeyFile: cfg.TLS.Key,
	})
	if err != nil {
		return fmt.Errorf("gvpn-server: GOST listen: %w", err)
	}
	defer ln.Close()
	return run(cfg, serveDeps{
		Listener: gostNetListener{Listener: ln},
		NewTUN:   realTUN,
		NAT:      iptablesNAT{},
		LogLevel: 0, // device.LogLevelSilent
	})
}

// cmdGencert generates a GOST server cert (default) or a standard cert (--standard).
func cmdGencert(args []string) error {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	standard := fs.Bool("standard", false, "generate a standard (non-GOST) cert for the share page")
	cn := fs.String("cn", "", "certificate common name / SAN (required)")
	certPath := fs.String("cert", "", "output certificate path (required)")
	keyPath := fs.String("key", "", "output private key path (required)")
	days := fs.Int("days", 825, "validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cn == "" || *certPath == "" || *keyPath == "" {
		return fmt.Errorf("gencert: --cn, --cert and --key are required")
	}
	if *standard {
		if err := generateStandardCert(*cn, *certPath, *keyPath, *days); err != nil {
			return err
		}
		fmt.Printf("wrote standard cert %s / key %s\n", *certPath, *keyPath)
		return nil
	}
	if err := gosttls.GenerateSelfSignedGOSTCert(*cn, *certPath, *keyPath, *days); err != nil {
		return err
	}
	fmt.Printf("wrote GOST cert %s / key %s\n", *certPath, *keyPath)
	return nil
}

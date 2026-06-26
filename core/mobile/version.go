package mobile

import "github.com/g00dvin/gvpn/core/gosttls"

// Version returns the linked OpenSSL/GOST version string. It is a harmless,
// no-argument bound call the Android shell uses to prove the .aar binding links
// at build time; it does not initialize the gost engine.
func Version() string {
	return gosttls.Version()
}

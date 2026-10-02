package jenkins

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// tlsInsecureConfig is isolated in its own file so the one place that disables
// certificate verification is easy to find and audit. Only the scan.insecure
// config key reaches it.
func tlsInsecureConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via scan.insecure
}

// tlsWithCAFile trusts the certificate authorities in a PEM bundle on top of
// the system pool — how a controller behind an internal CA is verified rather
// than not checked at all. Read and parsed here, at startup: a bundle that is
// missing or holds no certificate is a configuration error to report before
// the first request, not a handshake failure to puzzle over after it.
func tlsWithCAFile(path string) (*tls.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scan.caFile: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Some minimal containers have no enumerable system pool; the bundle
		// alone is then what is trusted.
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("scan.caFile %s: no PEM certificate found in it", path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

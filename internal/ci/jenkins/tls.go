package jenkins

import "crypto/tls"

// tlsInsecureConfig is isolated in its own file so the one place that disables
// certificate verification is easy to find and audit. Only the scan.insecure
// config key reaches it.
func tlsInsecureConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via scan.insecure
}

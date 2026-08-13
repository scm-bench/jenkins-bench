module github.com/scm-bench/jenkins-bench

go 1.25.0

// Pinned to a patched toolchain, not merely a recent one.
//
// The `go` directive above is a language version: it says nothing about which
// standard library a build ends up using, and the standard library is where
// this tool's vulnerabilities live. It makes TLS connections carrying a token
// that can read every job, credential and plugin on a controller, so "whatever
// Go the runner happened to install" is not good enough — go1.26.1 carried a
// reachable certificate-verification bypass in crypto/x509 and a TLS denial of
// service, among ten others, and nothing in the build would have said so.
//
// Raise this when govulncheck reports something new. CI runs it on every
// change so the reporting is not left to whoever remembers.
toolchain go1.26.5

require (
	github.com/spf13/cobra v1.10.2
	golang.org/x/term v0.45.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

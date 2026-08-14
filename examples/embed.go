// Package examples ships the bundled samples inside the binary. config.yaml
// is embedded from where the README points at it, so `init` cannot drift from
// the documented file. snapshot.json is deliberately not embedded: nothing in
// the binary consumes it.
package examples

import _ "embed"

// ConfigYAML is examples/config.yaml, byte for byte. `jenkins-bench init`
// writes it.
//
//go:embed config.yaml
var ConfigYAML []byte

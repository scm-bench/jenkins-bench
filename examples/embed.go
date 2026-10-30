// Package examples ships the bundled samples inside the binary. config.yaml
// is embedded from where the README points at it, so `init` cannot drift from
// the documented file. snapshot.json is embedded so `jenkins-bench scan --demo`
// works for someone who installed a release archive and has no checkout: the
// person who has not seen a report yet is exactly the one without a
// controller at hand.
package examples

import _ "embed"

// ConfigYAML is examples/config.yaml, byte for byte. `jenkins-bench init`
// writes it.
//
//go:embed config.yaml
var ConfigYAML []byte

// SnapshotJSON is examples/snapshot.json, byte for byte. `jenkins-bench scan
// --demo` evaluates it.
//
//go:embed snapshot.json
var SnapshotJSON []byte

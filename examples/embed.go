// Package examples ships the bundled samples inside the binary.
//
// These files began as things this repository carries for people reading it on
// GitHub — but a file in a git checkout helps nobody who installed a release
// binary, which is exactly the person `jenkins-bench init` exists for.
//
// config.yaml stays checked in here rather than moving next to the CLI,
// because it is also documentation: the README points at it, and embedding
// from where it already lives keeps `init` from drifting away from the file
// the README shows. snapshot.json is deliberately NOT embedded: nothing in the
// binary consumes it yet — it exists for `--snapshot-in examples/snapshot.json`
// from a checkout and as the release archives' sample — and an embed with no
// consumer is dead weight that reads like a feature.
package examples

import _ "embed"

// ConfigYAML is examples/config.yaml, byte for byte. `jenkins-bench init`
// writes it.
//
//go:embed config.yaml
var ConfigYAML []byte

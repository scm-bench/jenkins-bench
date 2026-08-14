// Package examples ships the bundled samples inside the binary.
//
// These files began as things this repository carries for people reading it on
// GitHub — but a file in a git checkout helps nobody who installed a release
// binary, which is exactly the person who has not seen a report yet.
//
// They stay checked in here rather than moving next to the CLI, because they
// are also documentation: the README points at them, and
// `--snapshot-in examples/snapshot.json` remains a way to evaluate the sample
// from a checkout. Embedding from where they already live keeps one copy, and
// keeps `jenkins-bench init` from drifting away from the file the README shows.
package examples

import _ "embed"

// ConfigYAML is examples/config.yaml, byte for byte. `jenkins-bench init`
// writes it.
//
//go:embed config.yaml
var ConfigYAML []byte

// SnapshotJSON is examples/snapshot.json, byte for byte.
//
//go:embed snapshot.json
var SnapshotJSON []byte

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Instance is the saved answer to "which instance, and as whom": what the
// first-run menu writes down — with consent — so the next scan does not ask
// again. It is deliberately not part of Config: that file is policy a team
// reviews and commits, this one is a credential that must never be.
type Instance struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// instanceFile is the name under the config directory.
const instanceFile = "instance.yaml"

// InstancePath is where the saved instance lives: BITBUCKET_BENCH_CONFIG_DIR when
// set — a pipeline pinning the location, a test staying out of the real one —
// otherwise the platform's user config directory.
func InstancePath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, instanceFile), nil
}

// LoadInstance reads the saved instance, returning a zero Instance and no
// error when none has been saved — absence is the normal first-run state, not
// a failure. The path comes back too, so callers can name where the values
// came from: a scan that silently picks up a credential from disk is a scan
// whose authentication failures cannot be debugged.
func LoadInstance() (Instance, string, error) {
	var inst Instance
	path, err := InstancePath()
	if err != nil {
		return inst, "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inst, path, nil
		}
		return inst, path, fmt.Errorf("read saved instance %s: %w", path, err)
	}
	// KnownFields for the same reason Load has it: `tokn:` parsing cleanly to
	// an instance with no token would send the user to debug an anonymous
	// scan's permissions instead of a typo.
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&inst); err != nil && !errors.Is(err, io.EOF) {
		return Instance{}, path, fmt.Errorf("parse saved instance %s: %w", path, err)
	}
	return inst, path, nil
}

// SaveInstance writes the instance for future runs and returns where it went.
//
// 0600 and a 0700 directory, for a stronger version of the reason snapshots
// get it: those describe an instance's weak points, this is a live credential
// that can read them all. The same Windows caveat applies — permission bits
// are not enforced there, and the README says so.
func SaveInstance(inst Instance) (string, error) {
	path, err := InstancePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	raw, err := yaml.Marshal(inst)
	if err != nil {
		return "", fmt.Errorf("encode instance: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("write saved instance %s: %w", path, err)
	}
	return path, nil
}

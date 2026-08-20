package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// The discovered config names, in the order they are tried. The visible name
// first: a file that changes how an audit judges an instance should be seen
// in a directory listing, but teams that keep tool files hidden get their
// convention respected.
var discoverNames = []string{"jenkins-bench.yaml", ".jenkins-bench.yaml"}

const userConfigFile = "config.yaml"

// Discover finds the config file an unadorned `jenkins-bench scan` should use:
// jenkins-bench.yaml (or .jenkins-bench.yaml) in the working directory first — the
// project's file, the one a repository commits for CI — then config.yaml
// under the user config directory (or JENKINS_BENCH_CONFIG_DIR), the person's
// own defaults. "" means none found, which is not an error: defaults are the
// normal state before anyone has run init.
//
// An explicit --config always wins over this; the caller enforces that by
// not calling Discover when one was given.
func Discover() (string, error) {
	for _, name := range discoverNames {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
	}
	dir, err := userConfigDir()
	if err != nil {
		// No user config directory means nothing to discover there, not a
		// broken scan.
		return "", nil
	}
	path := filepath.Join(dir, userConfigFile)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", nil
}

// userConfigDir is where per-user jenkins-bench files live, shared with the
// saved instance: JENKINS_BENCH_CONFIG_DIR when set, else the platform's user
// config directory.
func userConfigDir() (string, error) {
	if dir := os.Getenv("JENKINS_BENCH_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate the config directory: %w", err)
	}
	return filepath.Join(dir, "jenkins-bench"), nil
}

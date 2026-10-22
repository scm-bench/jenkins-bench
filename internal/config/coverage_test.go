package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurationRejectsWhatIsNotADuration(t *testing.T) {
	cases := map[string]string{
		"a sequence":   "scan:\n  timeout: [30]\n",
		"no unit word": "scan:\n  timeout: soon\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Errorf("%q was accepted as a duration", body)
			}
		})
	}
}

func TestSetRejectsValuesThatWouldInjectYAML(t *testing.T) {
	cases := map[string]string{
		"multi-line value": "scan.failOn=none\nthresholds: {}",
		"carriage return":  "scan.failOn=none\r",
		"bad key segment":  "scan.fail-on=none",
		"empty segment":    "scan..failOn=none",
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadWithOverrides("", []string{set}); err == nil {
				t.Errorf("--set %q was accepted", set)
			}
		})
	}
}

func TestValidateRejectsOutOfRangeScanSettings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"zero concurrency", func(c *Config) { c.Scan.Concurrency = 0 }, "scan.concurrency"},
		{"failUnder below 0", func(c *Config) { c.Scan.FailUnder = -1 }, "scan.failUnder"},
		{"failUnder above 100", func(c *Config) { c.Scan.FailUnder = 101 }, "scan.failUnder"},
		{"maxManual below -1", func(c *Config) { c.Scan.MaxManual = -2 }, "scan.maxManual"},
		{"maxManual above 100", func(c *Config) { c.Scan.MaxManual = 101 }, "scan.maxManual"},
		{"negative timeout", func(c *Config) { c.Scan.Timeout = Duration(-1) }, "must not be negative"},
		{"negative maxDuration", func(c *Config) { c.Scan.MaxDuration = Duration(-1) }, "must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %s", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsMaxManualDisabled(t *testing.T) {
	cfg := Default()
	cfg.Scan.MaxManual = -1
	if err := cfg.Validate(); err != nil {
		t.Errorf("-1 disables the check and should be accepted: %v", err)
	}
}

// noUserConfigDir makes os.UserConfigDir fail on every platform CI runs on.
func noUserConfigDir(t *testing.T) {
	t.Helper()
	for _, k := range []string{"JENKINS_BENCH_CONFIG_DIR", "XDG_CONFIG_HOME", "HOME", "AppData", "home"} {
		t.Setenv(k, "")
	}
}

func TestDiscoverPrefersTheWorkingDirectory(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	for _, name := range []string{".jenkins-bench.yaml", "jenkins-bench.yaml"} {
		if err := os.WriteFile(name, []byte("scan: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := Discover(); got != name {
			t.Errorf("Discover() = %q, want %q", got, name)
		}
	}
}

func TestDiscoverFallsBackToTheUserConfigDir(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", dir)

	if got := Discover(); got != "" {
		t.Fatalf("Discover() with no files = %q, want \"\"", got)
	}

	want := filepath.Join(dir, userConfigFile)
	if err := os.WriteFile(want, []byte("scan: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Discover(); got != want {
		t.Errorf("Discover() = %q, want %q", got, want)
	}
}

func TestDiscoverWithoutAUserConfigDirFindsNothing(t *testing.T) {
	t.Chdir(t.TempDir())
	noUserConfigDir(t)
	if got := Discover(); got != "" {
		t.Errorf("Discover() = %q, want \"\"", got)
	}
}

func TestUserConfigDirUsesThePlatformDefault(t *testing.T) {
	base := t.TempDir()
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base)
	t.Setenv("AppData", base)
	got, err := userConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "jenkins-bench" {
		t.Errorf("userConfigDir() = %q, want a jenkins-bench directory", got)
	}
}

func TestLoadNamesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("Load(missing) error = %v, want it to name %s", err, path)
	}
}

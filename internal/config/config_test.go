package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jenkins-bench.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Errorf("the defaults must pass their own validation: %v", err)
	}
}

func TestLoadWithNoPathReturnsTheDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.FailOn != Default().Scan.FailOn {
		t.Errorf("failOn = %q, want the default", cfg.Scan.FailOn)
	}
}

func TestLoadMergesOverTheDefaults(t *testing.T) {
	path := writeConfig(t, "scan:\n  failOn: medium\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.FailOn != "medium" {
		t.Errorf("failOn = %q", cfg.Scan.FailOn)
	}
	// A file that names one key must not blank the rest.
	if cfg.Scan.Concurrency != Default().Scan.Concurrency {
		t.Errorf("concurrency = %d, want the default to survive", cfg.Scan.Concurrency)
	}
	if cfg.Thresholds.UpdateSiteMaxAgeDays != Default().Thresholds.UpdateSiteMaxAgeDays {
		t.Error("thresholds should keep their defaults")
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	path := writeConfig(t, "scan:\n  failOnn: high\n")
	if _, err := Load(path); err == nil {
		t.Error("a misspelled key must be an error; silently ignoring it changes the run")
	}
}

func TestSetOverridesAKey(t *testing.T) {
	cfg, err := LoadWithOverrides("", []string{"scan.failOn=none", "scan.failUnder=70"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.FailOn != "none" || cfg.Scan.FailUnder != 70 {
		t.Errorf("scan = %+v", cfg.Scan)
	}
}

func TestSetRejectsNonsense(t *testing.T) {
	for _, bad := range []string{"failOn", "nosuch.key=1", "scan.failUnder=abc"} {
		if _, err := LoadWithOverrides("", []string{bad}); err == nil {
			t.Errorf("--set %q was accepted", bad)
		}
	}
}

// A negative threshold does not produce an odd number, it inverts the control
// it feeds — and nothing in the report would say so.
func TestNegativeThresholdsAreRejected(t *testing.T) {
	cfg := Default()
	cfg.Thresholds.UpdateSiteMaxAgeDays = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a negative threshold was accepted")
	}
	if !strings.Contains(err.Error(), "updateSiteMaxAgeDays") {
		t.Errorf("the error should name the field: %v", err)
	}
}

// A blank entry in include selects nothing rather than everything, and one in
// exclude is a line somebody meant to fill in. Neither errors later.
func TestBlankListEntriesAreRejected(t *testing.T) {
	for _, field := range []string{"exclude", "include"} {
		cfg := Default()
		switch field {
		case "exclude":
			cfg.Exclude = []string{"CIS-2.1.6", ""}
		case "include":
			cfg.Include = []string{""}
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("a blank entry in %s was accepted", field)
		}
	}
}

func TestSelectsHonoursIncludeAndExclude(t *testing.T) {
	cfg := Default()
	if !cfg.Selects("CIS-2.1.6") {
		t.Error("with neither list set, everything is selected")
	}

	cfg.Exclude = []string{"CIS-2.1.6"}
	if cfg.Selects("CIS-2.1.6") {
		t.Error("exclude should drop the control")
	}

	cfg = Default()
	cfg.Include = []string{"CIS-2.1.6"}
	if !cfg.Selects("CIS-2.1.6") {
		t.Error("include should keep the named control")
	}
	if cfg.Selects("CIS-2.3.1") {
		t.Error("include should drop everything it does not name")
	}
}

func TestFailOnIsValidated(t *testing.T) {
	cfg := Default()
	cfg.Scan.FailOn = "critical"
	if err := cfg.Validate(); err == nil {
		t.Error("an unknown severity should be rejected rather than matching nothing")
	}
}

func TestDurationParsesHumanValues(t *testing.T) {
	path := writeConfig(t, "scan:\n  timeout: 45s\n  maxDuration: 5m\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Timeout.Get().Seconds() != 45 {
		t.Errorf("timeout = %v", cfg.Scan.Timeout.Get())
	}
	if cfg.Scan.MaxDuration.Get().Minutes() != 5 {
		t.Errorf("maxDuration = %v", cfg.Scan.MaxDuration.Get())
	}
}

// The thresholds reach Rego as input.config verbatim, and the scan section must
// not: no rule reads it, and keeping it out leaves input.config byte-identical
// between two runs that differ only in how they were driven.
func TestScanSectionIsNotHandedToPolicies(t *testing.T) {
	cfg := Default()
	cfg.Scan.FailOn = "none"
	encoded, err := marshalForPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "failOn") || strings.Contains(encoded, "concurrency") {
		t.Errorf("the scan section reached the policy input:\n%s", encoded)
	}
	if !strings.Contains(encoded, "updateSiteMaxAgeDays") {
		t.Errorf("thresholds should reach the policy input:\n%s", encoded)
	}
}

// marshalForPolicy renders the config the way the engine hands it to Rego.
func marshalForPolicy(c Config) (string, error) {
	body, err := json.Marshal(c)
	return string(body), err
}

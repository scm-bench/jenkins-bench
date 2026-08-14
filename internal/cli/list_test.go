package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// run executes the command tree with the given arguments, capturing stdout.
func run(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

func TestListChecksPrintsEveryControl(t *testing.T) {
	got := run(t, "list-checks")

	for _, want := range []string{"ID", "SEVERITY", "SCOPE", "AUTOMATED", "TITLE", "CIS-2.1.6"} {
		if !strings.Contains(got, want) {
			t.Errorf("list-checks output is missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "controls") {
		t.Errorf("list-checks should print a count:\n%s", got)
	}
}

// The scope column is what tells a reader whether a finding will appear once or
// once per job, so a bundle whose scopes did not load would be invisible here.
func TestListChecksPrintsScopes(t *testing.T) {
	got := run(t, "list-checks")
	if !strings.Contains(got, "controller") && !strings.Contains(got, "job") {
		t.Errorf("expected at least one control scope in the output:\n%s", got)
	}
}

func TestListChecksJSONIsMachineReadable(t *testing.T) {
	got := run(t, "list-checks", "--json")

	var checks []struct {
		ID         string   `json:"id"`
		Scope      string   `json:"scope"`
		Severity   string   `json:"severity"`
		Platforms  []string `json:"platforms"`
		FixSummary string   `json:"fixSummary"`
	}
	if err := json.Unmarshal([]byte(got), &checks); err != nil {
		t.Fatalf("--json did not produce valid JSON: %v\n%s", err, got)
	}
	if len(checks) == 0 {
		t.Fatal("--json produced an empty list")
	}
	for _, c := range checks {
		if c.ID == "" || c.Scope == "" || c.Severity == "" || c.FixSummary == "" {
			t.Errorf("control %+v is missing a required field", c)
		}
		if len(c.Platforms) == 0 {
			t.Errorf("control %s names no platform", c.ID)
		}
	}
}

// HTML escaping in the JSON encoder turns the ">" in a settings path into
// "\u003e", which is valid JSON and unreadable to the person who asked for the
// remediation text.
func TestListChecksJSONDoesNotEscapeHTML(t *testing.T) {
	got := run(t, "list-checks", "--json")
	if strings.Contains(got, `\u003e`) || strings.Contains(got, `\u0026`) {
		t.Error("--json escaped HTML characters in the metadata")
	}
}

func TestVersionPrintsBuildInformation(t *testing.T) {
	got := run(t, "version")
	if !strings.Contains(got, "jenkins-bench") {
		t.Errorf("version output should name the tool:\n%s", got)
	}
	for _, want := range []string{"commit:", "built:", "go:"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output is missing %q:\n%s", want, got)
		}
	}
}

func TestRootCommandRegistersItsSubcommands(t *testing.T) {
	root := NewRootCommand()
	want := map[string]bool{"list-checks": false, "version": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("root command does not register %q", name)
		}
	}
}

package checks

import (
	"path"
	"strings"
	"testing"
)

func TestBundleLoads(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The floor is 1, not a coverage target. What this guards is the embed:
	// //go:embed over policies/*/*/ fails to compile when nothing matches, but
	// a directory renamed out from under the pattern loads an empty bundle and
	// every scan then reports zero findings and a clean score.
	if len(bundle.Checks) == 0 {
		t.Error("bundle is empty; the embed pattern matched no controls")
	}
	if len(bundle.Modules) < len(bundle.Checks) {
		t.Errorf("bundle has %d modules for %d checks", len(bundle.Modules), len(bundle.Checks))
	}
}

// The Rego package declared in metadata has to match the module sitting next to
// it, otherwise the engine silently evaluates the wrong rule or none at all.
func TestEveryCheckHasAMatchingModule(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	packagesByDir := map[string]string{}
	for _, m := range bundle.Modules {
		for _, line := range strings.Split(m.Source, "\n") {
			line = strings.TrimSpace(line)
			if pkg, ok := strings.CutPrefix(line, "package "); ok {
				packagesByDir[path.Dir(m.Path)] = strings.TrimSpace(pkg)
				break
			}
		}
	}

	for _, c := range bundle.Checks {
		declared, ok := packagesByDir[c.Dir]
		if !ok {
			t.Errorf("%s: no Rego module in %s", c.ID, c.Dir)
			continue
		}
		if declared != c.Package {
			t.Errorf("%s: metadata declares package %q but the module declares %q", c.ID, c.Package, declared)
		}
	}
}

// Remediation is the part of a finding that gets acted on. A vague one is worse
// than useless, so every control must say where to go: a settings path, the
// file to add, or an explicit statement that nothing applies.
func TestRemediationSaysWhereToAct(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The categories below are this domain's places to act. The reference
	// implementation needed only the first three, because every Bitbucket fix
	// is a settings path — but half of a Jenkins controller's remediation
	// happens outside the controller, and "configure your security groups" is
	// as concrete as a UI path without ever containing "->".
	namesALocation := func(remediation string) bool {
		lower := strings.ToLower(remediation)
		switch {
		case strings.Contains(remediation, "->"): // a UI settings path
			return true
		case strings.Contains(remediation, ".md"): // a file to add
			return true
		case strings.Contains(lower, "no action applies"), strings.Contains(remediation, "无需处理"):
			// The control is NA; saying so plainly is the correct remediation.
			return true
		case strings.Contains(lower, "system property"): // startup configuration
			return true
		case strings.Contains(lower, "settings"): // a named settings page, wherever it lives
			return true
		case strings.Contains(lower, "registry"): // the image or artifact registry
			return true
		case strings.Contains(lower, "security group"): // the network boundary around agents
			return true
		}
		return false
	}

	for _, c := range bundle.Checks {
		if len(c.Remediation) < 40 {
			t.Errorf("%s: remediation is too terse to act on: %q", c.ID, c.Remediation)
		}
		if !namesALocation(c.Remediation) {
			t.Errorf("%s: remediation does not say where to act: %q", c.ID, c.Remediation)
		}
		if c.Description == "" {
			t.Errorf("%s: description is empty", c.ID)
		}
		if len(c.References) == 0 {
			t.Errorf("%s: no references", c.ID)
		}
	}

	// The summary rides beside the verdict, so it has to earn its line: one
	// sentence, still naming a place, and short enough to survive wrapping into
	// a narrow terminal without pushing the finding off the screen.
	for _, c := range bundle.Checks {
		if len(c.FixSummary) > 100 {
			t.Errorf("%s: fixSummary is %d characters, want at most 100: %q", c.ID, len(c.FixSummary), c.FixSummary)
		}
		if !namesALocation(c.FixSummary) {
			t.Errorf("%s: fixSummary does not say where to act: %q", c.ID, c.FixSummary)
		}
		if strings.Contains(c.FixSummary, "\n") {
			t.Errorf("%s: fixSummary must be a single line: %q", c.ID, c.FixSummary)
		}
	}
}

func TestChecksAreSortedByBenchmarkNumber(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Stated over whatever the bundle happens to hold, rather than by naming
	// two IDs that must be in it: the ordering is the property, and a test
	// pinned to specific controls stops testing it the moment they change.
	// TestLessCISID covers the numeric-versus-lexical case that motivates it.
	// Controls without a benchmark number are supplements and sort after the
	// mapping, so a reader meets the benchmark first.
	for i := 1; i < len(bundle.Checks); i++ {
		prev, cur := bundle.Checks[i-1], bundle.Checks[i]
		switch {
		case prev.CISID == "" && cur.CISID != "":
			t.Errorf("supplementary %s sorts before mapped %s", prev.ID, cur.ID)
		case prev.CISID != "" && cur.CISID != "" && LessCISID(cur.CISID, prev.CISID):
			t.Errorf("bundle is out of benchmark order: %s comes before %s", prev.CISID, cur.CISID)
		}
	}
}

func TestWeightsFollowSeverity(t *testing.T) {
	if Weight(SeverityHigh) <= Weight(SeverityMedium) || Weight(SeverityMedium) <= Weight(SeverityLow) {
		t.Error("weights must be strictly decreasing from HIGH to LOW")
	}
	if Weight("nonsense") != Weight(SeverityLow) {
		t.Error("an unknown severity should weigh the least, not the most")
	}
}

func TestAppliesTo(t *testing.T) {
	c := Check{Metadata: Metadata{Platforms: []string{"jenkins"}}}
	if !c.AppliesTo("JENKINS") {
		t.Error("platform matching should be case-insensitive")
	}
	if c.AppliesTo("github") {
		t.Error("a jenkins-only check must not apply to github")
	}
}

func TestLessCISID(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.1.9", "1.1.11", true},
		{"1.1.11", "1.1.9", false},
		{"1.1.3", "1.2.1", true},
		{"1.2.1", "1.1.17", false},
		{"1.1", "1.1.1", true},
	}
	for _, tc := range tests {
		if got := LessCISID(tc.a, tc.b); got != tc.want {
			t.Errorf("LessCISID(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// The Rego unit tests live beside the rules they test, which is where a
// maintainer expects them and where `opa test` looks. They must not reach the
// bundle: compiling them into the engine would put assertion rules in the same
// namespace as verdicts, and every released binary would carry them.
func TestBundleContainsNoTestModules(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	for _, m := range bundle.Modules {
		if strings.HasSuffix(m.Path, "_test.rego") {
			t.Errorf("bundle carries the test module %s", m.Path)
		}
		if strings.Contains(m.Source, "scmbench.testdata") {
			t.Errorf("module %s references the test fixtures", m.Path)
		}
	}
}

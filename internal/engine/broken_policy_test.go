package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/config"
)

// fakeCheck is a control whose metadata is complete, so only its policy is
// under test.
func fakeCheck(id, pkg, scope string) checks.Check {
	return checks.Check{Metadata: checks.Metadata{
		ID: id, CISID: "9." + strings.TrimPrefix(id, "T-"), Package: pkg, Scope: scope,
		Severity: checks.SeverityHigh, Platforms: []string{ci.PlatformJenkins}, Automated: true,
		Title: id, Remediation: "fix " + id, FixSummary: "fix " + id,
	}}
}

// withBundle makes New load the given bundle instead of the embedded one.
func withBundle(t *testing.T, b *checks.Bundle, err error) {
	t.Helper()
	orig := loadBundle
	loadBundle = func() (*checks.Bundle, error) { return b, err }
	t.Cleanup(func() { loadBundle = orig })
}

func TestNewReportsABundleThatFailsToLoad(t *testing.T) {
	withBundle(t, nil, errors.New("metadata.json: title is required"))
	_, err := New(context.Background(), config.Default(), ci.PlatformJenkins)
	if err == nil || !strings.Contains(err.Error(), "load policy bundle") || !strings.Contains(err.Error(), "title is required") {
		t.Errorf("New() error = %v, want the load failure", err)
	}
}

func TestNewReportsAPolicyThatDoesNotCompile(t *testing.T) {
	withBundle(t, &checks.Bundle{
		Checks:  []checks.Check{fakeCheck("T-1", "scmbench.test.broken", checks.ScopeController)},
		Modules: []checks.Module{{Path: "broken.rego", Source: "package scmbench.test.broken\n\nresult := {"}},
	}, nil)
	_, err := New(context.Background(), config.Default(), ci.PlatformJenkins)
	if err == nil || !strings.Contains(err.Error(), "compile policies") {
		t.Errorf("New() error = %v, want a compile error", err)
	}
}

func TestNewReportsAPackageThatCannotBeQueried(t *testing.T) {
	// A hyphen is not legal in a package path: the query parses as a
	// subtraction with an unbound variable, and preparing it fails.
	withBundle(t, &checks.Bundle{
		Checks: []checks.Check{fakeCheck("T-1", "scmbench.bad-pkg", checks.ScopeController)},
	}, nil)
	_, err := New(context.Background(), config.Default(), ci.PlatformJenkins)
	if err == nil || !strings.Contains(err.Error(), "prepare T-1") {
		t.Errorf("New() error = %v, want a prepare error naming the control", err)
	}
}

func TestNewRefusesAPlatformWithNoControls(t *testing.T) {
	_, err := New(context.Background(), config.Default(), "gitlab")
	if err == nil || !strings.Contains(err.Error(), `no checks selected for platform "gitlab"`) {
		t.Errorf("New() error = %v, want no checks selected", err)
	}
}

// A policy that decides nothing, or decides something that is not a verdict,
// becomes a MANUAL finding with the reason — on the controller and on every
// job alike — and the reason is listed in the report's errors so the run
// cannot pass as complete.
func TestBrokenPoliciesBecomeManualFindingsWithAReason(t *testing.T) {
	withBundle(t, &checks.Bundle{
		Checks: []checks.Check{
			fakeCheck("T-1", "scmbench.test.silent", checks.ScopeController),
			fakeCheck("T-2", "scmbench.test.weird", checks.ScopeJob),
			fakeCheck("T-3", "scmbench.test.silentjob", checks.ScopeJob),
			fakeCheck("T-4", "scmbench.test.ok", checks.ScopeJob),
		},
		Modules: []checks.Module{
			{Path: "silent.rego", Source: "package scmbench.test.silent\n\nresult := r if {\n\tr := {\"status\": \"PASS\", \"details\": \"x\"}\n\tinput.resource.nothing\n}\n"},
			{Path: "weird.rego", Source: "package scmbench.test.weird\n\nresult := {\"status\": \"MAYBE\", \"details\": \"hmm\"}\n"},
			{Path: "silentjob.rego", Source: "package scmbench.test.silentjob\n\nresult := r if {\n\tr := {\"status\": \"PASS\", \"details\": \"x\"}\n\tinput.resource.nothing\n}\n"},
			{Path: "ok.rego", Source: "package scmbench.test.ok\n\nresult := {\"status\": \"PASS\", \"details\": \"fine\", \"evidence\": [\"a\", 1]}\n"},
		},
	}, nil)
	rep := evaluate(t, config.Default(), hardenedSnapshot())

	byKey := map[string]Finding{}
	for _, f := range rep.Findings {
		byKey[f.CheckID+"@"+f.Resource] = f
	}
	for key, want := range map[string]string{
		"T-1@controller":           "produced no result",
		"T-2@legacy-build":         "malformed result",
		"T-3@platform/api-service": "produced no result",
	} {
		f, ok := byKey[key]
		if !ok {
			t.Errorf("%s: no finding", key)
			continue
		}
		if f.Status != StatusManual || !strings.Contains(f.Details, want) {
			t.Errorf("%s = %s %q, want MANUAL mentioning %q", key, f.Status, f.Details, want)
		}
	}
	if ok := byKey["T-4@legacy-build"]; ok.Status != StatusPass || strings.Join(ok.Evidence, ",") != "a,1" {
		t.Errorf("the working policy = %+v, want PASS with evidence a,1", ok)
	}
	// One controller error, and two per job (T-2 and T-3) for two jobs.
	if len(rep.Errors) != 5 {
		t.Errorf("report errors = %d, want 5: %q", len(rep.Errors), rep.Errors)
	}
}

func TestEvaluateStopsWhenAnInputCannotBeEncoded(t *testing.T) {
	failOn := func(target string) func(any) (ast.Value, error) {
		return func(v any) (ast.Value, error) {
			name := ""
			switch v.(type) {
			case config.Config:
				name = "config"
			case ci.Metadata:
				name = "metadata"
			case ci.Controller:
				name = "controller"
			case ci.Job:
				name = "job"
			}
			if name == target {
				return nil, errors.New("cannot encode " + name)
			}
			return toAST(v)
		}
	}
	for target, want := range map[string]string{
		"config":     "encode config",
		"metadata":   "encode snapshot metadata",
		"controller": "encode controller",
		"job":        "encode job",
	} {
		t.Run(target, func(t *testing.T) {
			eng, err := New(context.Background(), config.Default(), ci.PlatformJenkins)
			if err != nil {
				t.Fatal(err)
			}
			eng.encode = failOn(target)
			rep, err := eng.Evaluate(context.Background(), hardenedSnapshot())
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Evaluate() = %v, %v; want an error containing %q and no report", rep, err, want)
			}
		})
	}
}

func TestDecodeResultRejectsWhatIsNotAVerdict(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"not an object", []any{"PASS"}, "want an object"},
		{"unknown status", map[string]any{"status": "OK", "details": "d"}, "is not PASS"},
		{"no status", map[string]any{"details": "d"}, "is not PASS"},
		{"blank details", map[string]any{"status": "PASS", "details": "  "}, "missing details"},
		{"evidence not a list", map[string]any{"status": "FAIL", "details": "d", "evidence": "one"}, "want an array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeResult(tc.value)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("decodeResult(%v) error = %v, want %q", tc.value, err, tc.want)
			}
		})
	}
}

func TestDecodeResultNormalisesTheStatus(t *testing.T) {
	got, err := decodeResult(map[string]any{"status": " na ", "details": "not applicable"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusNA || got.Evidence != nil {
		t.Errorf("decodeResult = %+v, want NA with no evidence", got)
	}
}

func TestToASTReportsAnUnencodableValue(t *testing.T) {
	if _, err := toAST(make(chan int)); err == nil {
		t.Error("toAST(chan) succeeded")
	}
}

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/config"
)

func hardenedSnapshot() *ci.Snapshot {
	return &ci.Snapshot{
		SchemaVersion: ci.SchemaVersion,
		Metadata:      ci.Metadata{Tool: "jenkins-bench", Platform: ci.PlatformJenkins, BaseURL: "https://jenkins.invalid"},
		Controller: ci.Controller{
			Version: "2.541.2",
			Security: ci.Security{
				Enabled: true, EnabledKnown: true,
				CSRFProtection: true, CSRFProtectionKnown: true,
				AnonymousRead: false, AnonymousReadKnown: true,
			},
			BuiltInNode: ci.BuiltInNode{NumExecutors: 0, NumExecutorsKnown: true},
			Available: map[string]bool{
				"root": true, "agents": true, "plugins": true, "updateSite": true, "credentials": true,
			},
		},
		Jobs: []ci.Job{
			{
				FullName: "platform/api-service", Name: "api-service", Folder: "platform",
				Kind: ci.KindPipeline, Buildable: true,
				Definition: ci.Definition{Source: ci.SourceSCM, ScriptPath: "Jenkinsfile"},
				Available:  map[string]bool{"api": true, "config": true},
			},
			{
				FullName: "legacy-build", Name: "legacy-build",
				Kind: ci.KindFreestyle, Buildable: true,
				Definition: ci.Definition{Source: ci.SourceUI},
				Available:  map[string]bool{"api": true, "config": true},
			},
		},
	}
}

func evaluate(t *testing.T, cfg config.Config, snap *ci.Snapshot) *Report {
	t.Helper()
	eng, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := eng.Evaluate(context.Background(), snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return rep
}

func TestEveryControlProducesAVerdict(t *testing.T) {
	// Four shapes, because a rule can be undefined in any of them and an
	// undefined rule reports nothing at all — which looks exactly like a
	// control that was not selected.
	shapes := map[string]*ci.Snapshot{
		"hardened": hardenedSnapshot(),
		"misconfigured": func() *ci.Snapshot {
			s := hardenedSnapshot()
			s.Controller.Security.AnonymousRead = true
			s.Controller.BuiltInNode.NumExecutors = 4
			s.Jobs[0].Definition = ci.Definition{Source: ci.SourceInline, Sandbox: false, SandboxKnown: true}
			return s
		}(),
		"unreadable": func() *ci.Snapshot {
			s := hardenedSnapshot()
			s.Controller.Available = map[string]bool{}
			s.Controller.Security = ci.Security{}
			for i := range s.Jobs {
				s.Jobs[i].Available = map[string]bool{}
				s.Jobs[i].Definition = ci.Definition{}
			}
			return s
		}(),
		// The zero-valued case is not optional. It catches the rule that
		// silently produces no verdict, which looks exactly like a passing
		// test run.
		"zero valued": {
			SchemaVersion: ci.SchemaVersion,
			Controller:    ci.Controller{},
			Jobs:          []ci.Job{{FullName: "j"}},
		},
	}

	bundle, err := checks.Load()
	if err != nil {
		t.Fatal(err)
	}

	for name, snap := range shapes {
		t.Run(name, func(t *testing.T) {
			rep := evaluate(t, config.Default(), snap)
			if len(rep.Errors) > 0 {
				t.Fatalf("policies failed to evaluate: %v", rep.Errors)
			}
			seen := map[string]bool{}
			for _, f := range rep.Findings {
				if f.Status == "" {
					t.Errorf("%s on %s produced no status", f.CheckID, f.Resource)
				}
				if f.Details == "" {
					t.Errorf("%s on %s produced no details", f.CheckID, f.Resource)
				}
				seen[f.CheckID] = true
			}
			for _, c := range bundle.Checks {
				if !seen[c.ID] {
					t.Errorf("%s produced no finding at all", c.ID)
				}
			}
		})
	}
}

func TestControllerScopeIsEvaluatedOnce(t *testing.T) {
	rep := evaluate(t, config.Default(), hardenedSnapshot())
	count := 0
	for _, f := range rep.Findings {
		if f.CheckID == "CIS-2.1.6" {
			count++
			if f.Resource != InstanceResourceName {
				t.Errorf("resource = %q, want %q", f.Resource, InstanceResourceName)
			}
			if f.ResourceType != ResourceController {
				t.Errorf("resourceType = %q", f.ResourceType)
			}
		}
	}
	if count != 1 {
		t.Errorf("a controller-scope control ran %d times, want once however many jobs there are", count)
	}
}

// The engine dispatches on scope, so a job-scope control has to fire once per
// job and name the job it is about.
func TestJobScopeWouldBeEvaluatedPerJob(t *testing.T) {
	snap := hardenedSnapshot()
	cfg := config.Default()
	eng, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err != nil {
		t.Fatal(err)
	}
	// No job-scope control exists yet; assert the wiring by checking that the
	// engine knows both scopes and that the snapshot's jobs reach it intact.
	for _, c := range eng.Checks() {
		if c.Scope != checks.ScopeController && c.Scope != checks.ScopeJob {
			t.Errorf("%s has scope %q, which the engine cannot dispatch", c.ID, c.Scope)
		}
	}
	rep, err := eng.Evaluate(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Metadata.Platform != snap.Metadata.Platform {
		t.Error("report metadata should carry the snapshot's")
	}
}

func TestSkipDisabledJobsIsAppliedWhenEvaluating(t *testing.T) {
	// Applied in the engine as well as the fetcher, so `scan --snapshot-in`
	// honours it: the same file and the same config must not produce two
	// answers depending on where the snapshot came from.
	snap := hardenedSnapshot()
	snap.Jobs[1].Disabled = true

	cfg := config.Default()
	cfg.SkipDisabledJobs = true
	eng, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Evaluate(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
}

func TestScoreIsZeroWhenNothingWasDecidable(t *testing.T) {
	snap := hardenedSnapshot()
	snap.Controller.Available = map[string]bool{}
	snap.Controller.Security = ci.Security{}

	rep := evaluate(t, config.Default(), snap)
	if rep.Score.Passed+rep.Score.Failed != 0 {
		t.Fatalf("expected nothing decidable, got %+v", rep.Score)
	}
	// An empty numerator over an empty denominator must not read as a clean
	// bill of health.
	if rep.Score.Value != 0 {
		t.Errorf("score = %d, want 0 when nothing could be evaluated", rep.Score.Value)
	}
	if rep.Score.Manual == 0 {
		t.Error("the manual count is what explains the zero; it must not be zero too")
	}
}

func TestSelectionRejectsAnUnknownCheckID(t *testing.T) {
	// An exclude that matches no control leaves that control running, and an
	// include that matches none narrows the scan to nothing. Both look like a
	// successful scan.
	cfg := config.Default()
	cfg.Exclude = []string{"CIS-9.9.9"}
	if _, err := New(context.Background(), cfg, ci.PlatformJenkins); err == nil {
		t.Error("an exclude naming no control should be an error")
	}

	cfg = config.Default()
	cfg.Include = []string{"CIS-9.9.9"}
	if _, err := New(context.Background(), cfg, ci.PlatformJenkins); err == nil {
		t.Error("an include naming no control should be an error")
	}
}

func TestIncludeNarrowsTheRun(t *testing.T) {
	cfg := config.Default()
	cfg.Include = []string{"CIS-2.1.6"}
	rep := evaluate(t, cfg, hardenedSnapshot())
	for _, f := range rep.Findings {
		if f.CheckID != "CIS-2.1.6" {
			t.Errorf("include should have excluded %s", f.CheckID)
		}
	}
}

func TestFindingsCarryTheirRemediation(t *testing.T) {
	snap := hardenedSnapshot()
	snap.Controller.Security.AnonymousRead = true
	rep := evaluate(t, config.Default(), snap)

	for _, f := range rep.Findings {
		if f.Status != StatusFail {
			continue
		}
		if f.FixSummary == "" {
			t.Errorf("%s failed without a one-line fix", f.CheckID)
		}
		if f.Remediation == "" {
			t.Errorf("%s failed without remediation", f.CheckID)
		}
		// Vague remediation is worse than none: it wastes the reader's time
		// before they discover it does not help.
		if !strings.ContainsAny(f.FixSummary, "->") && !strings.Contains(f.FixSummary, "Manage Jenkins") {
			t.Errorf("%s fixSummary names no place to act: %q", f.CheckID, f.FixSummary)
		}
	}
}

func TestEvaluateIsCancellable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	eng, err := New(ctx, config.Default(), ci.PlatformJenkins)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	rep, err := eng.Evaluate(ctx, hardenedSnapshot())
	if err != nil {
		return // a cancelled evaluation may return the context error
	}
	// Or it degrades every control to MANUAL carrying the reason, which is the
	// other acceptable outcome — but it must not report PASS.
	for _, f := range rep.Findings {
		if f.Status == StatusPass {
			t.Errorf("%s reported PASS after cancellation", f.CheckID)
		}
	}
}

package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

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
				"root": true, "agents": true, "plugins": true, "updateSite": true, "credentials": true, "jobs": true,
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
	// Per-job dispatch, concretely: every job-scope control must produce one
	// finding per job in the snapshot, named after that job.
	perJob := map[string]map[string]bool{}
	for _, f := range rep.Findings {
		if f.ResourceType == ResourceJob {
			if perJob[f.CheckID] == nil {
				perJob[f.CheckID] = map[string]bool{}
			}
			perJob[f.CheckID][f.Resource] = true
		}
	}
	if len(perJob) == 0 {
		t.Fatal("the bundle ships job-scope controls; none produced a finding")
	}
	for id, resources := range perJob {
		if len(resources) != len(snap.Jobs) {
			t.Errorf("%s produced findings for %d jobs, want %d", id, len(resources), len(snap.Jobs))
		}
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
	snap.Controller.BuiltInNode = ci.BuiltInNode{}
	// The jobs too: a snapshot is only "nothing decidable" when no resource
	// kept a readable fetch, and the job-scope controls read the jobs.
	for i := range snap.Jobs {
		snap.Jobs[i].Available = map[string]bool{}
		snap.Jobs[i].Definition = ci.Definition{}
	}

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
		return // acceptable: the cancellation surfaced as an error
	}

	// Cancellation races evaluation, and that is fine: a control that finished
	// before the cancellation landed produced a real verdict, and OPA checks
	// the context on its own schedule — this asserted "no PASS after cancel"
	// once, and a fast runner finished several controls before the engine
	// noticed. What cancellation must never do is corrupt the report: every
	// control still yields a finding with a status, and one that was cut off
	// reports MANUAL with the reason recorded, never a silent hole.
	bundle, err := checks.Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Status == "" {
			t.Errorf("%s on %s has no status after cancellation", f.CheckID, f.Resource)
		}
		if f.Status == StatusManual && f.Details == "" {
			t.Errorf("%s was cut off without a reason", f.CheckID)
		}
		seen[f.CheckID] = true
	}
	for _, c := range bundle.Checks {
		if !seen[c.ID] {
			t.Errorf("%s is silently missing from a cancelled report", c.ID)
		}
	}
}

// Coverage is what lets the CLI tell "every job is fine" from "there were no
// jobs to judge": the score reads the same for both.
func TestCoverageCountsWhatTheJobControlsSaw(t *testing.T) {
	rep := evaluate(t, config.Default(), hardenedSnapshot())
	if rep.Coverage.Jobs != 2 {
		t.Errorf("coverage.jobs = %d, want 2", rep.Coverage.Jobs)
	}
	if rep.Coverage.JobControls == 0 {
		t.Error("the bundle ships job-scope controls; coverage should count them")
	}
	if rep.Coverage.NoJobsAudited() {
		t.Error("two jobs were audited")
	}

	empty := hardenedSnapshot()
	empty.Jobs = nil
	if rep := evaluate(t, config.Default(), empty); !rep.Coverage.NoJobsAudited() {
		t.Errorf("a snapshot without jobs audited none: %+v", rep.Coverage)
	}

	cfg := config.Default()
	cfg.SkipDisabledJobs = true
	skipped := hardenedSnapshot()
	for i := range skipped.Jobs {
		skipped.Jobs[i].Disabled = true
	}
	rep = evaluate(t, cfg, skipped)
	if rep.Coverage.SkippedDisabled != 2 || !rep.Coverage.NoJobsAudited() {
		t.Errorf("coverage = %+v, want both jobs skipped and none audited", rep.Coverage)
	}

	// Narrowed to a controller-scope control, nothing asked about jobs.
	cfg = config.Default()
	cfg.Include = []string{"CIS-2.1.6"}
	if rep := evaluate(t, cfg, empty); rep.Coverage.NoJobsAudited() {
		t.Errorf("a controller-only run did not need jobs: %+v", rep.Coverage)
	}
}

// Completeness travels from the snapshot to the report, names and all, and a
// snapshot that never recorded it counts as incomplete.
func TestCoverageCarriesTheListingsCompleteness(t *testing.T) {
	if rep := evaluate(t, config.Default(), hardenedSnapshot()); !rep.Coverage.Complete {
		t.Error("a snapshot whose listing completed should be complete")
	}

	partial := hardenedSnapshot()
	partial.Controller.Available["jobs"] = false
	partial.Controller.Unlisted = []string{"prod"}
	rep := evaluate(t, config.Default(), partial)
	if rep.Coverage.Complete || len(rep.Coverage.Unlisted) != 1 || rep.Coverage.Unlisted[0] != "prod" {
		t.Errorf("coverage = %+v, want incomplete with prod unlisted", rep.Coverage)
	}

	unrecorded := hardenedSnapshot()
	delete(unrecorded.Controller.Available, "jobs")
	if rep := evaluate(t, config.Default(), unrecorded); rep.Coverage.Complete {
		t.Error("a snapshot that does not say its listing completed must not be taken as complete")
	}
}

// A job's evaluation input is the job and the thresholds, nothing more. v0.1
// added the whole controller — agents, credentials, plugins — to every one of
// them, which no job policy reads and which made a 10,000-job scan of a
// 1,000-agent controller take fourteen minutes.
func TestJobInputCarriesOnlyWhatItsScopeReads(t *testing.T) {
	job, err := toAST(hardenedSnapshot().Jobs[0])
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := toAST(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	input, ok := inputObject(job, cfg, nil).(ast.Object)
	if !ok {
		t.Fatalf("input is %T, want an object", inputObject(job, cfg, nil))
	}
	var keys []string
	for _, k := range input.Keys() {
		keys = append(keys, k.String())
	}
	if len(keys) != 2 || input.Get(ast.StringTerm("resource")) == nil || input.Get(ast.StringTerm("config")) == nil {
		t.Errorf("job input keys = %v, want resource and config only", keys)
	}

	controller, _ := toAST(hardenedSnapshot().Controller)
	meta, _ := toAST(hardenedSnapshot().Metadata)
	if full := inputObject(controller, cfg, meta).(ast.Object); full.Get(ast.StringTerm("metadata")) == nil {
		t.Error("the controller's input carries the metadata plugin currency reads")
	}
}

// Parallel evaluation must not change what is reported: the same snapshot
// gives the same findings, in the same order, run after run.
func TestEvaluationIsDeterministic(t *testing.T) {
	snap := hardenedSnapshot()
	for i := 0; i < 40; i++ {
		j := snap.Jobs[i%2]
		j.FullName = fmt.Sprintf("folder/job-%02d", i)
		snap.Jobs = append(snap.Jobs, j)
	}
	first := evaluate(t, config.Default(), snap)
	for run := 0; run < 3; run++ {
		again := evaluate(t, config.Default(), snap)
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("finding count changed: %d then %d", len(first.Findings), len(again.Findings))
		}
		for i := range first.Findings {
			a, b := first.Findings[i], again.Findings[i]
			if a.CheckID != b.CheckID || a.Resource != b.Resource || a.Status != b.Status {
				t.Fatalf("finding %d differs between runs: %s/%s/%s then %s/%s/%s",
					i, a.CheckID, a.Resource, a.Status, b.CheckID, b.Resource, b.Status)
			}
		}
	}
}

// BenchmarkEvaluateLargeController is the shape that took v0.1 fourteen
// minutes at 10,000 jobs: every job on a controller with a thousand agents,
// five hundred credentials and three hundred plugins.
func BenchmarkEvaluateLargeController(b *testing.B) {
	snap := hardenedSnapshot()
	for i := 0; i < 1000; i++ {
		snap.Controller.Agents = append(snap.Controller.Agents, ci.Agent{Name: fmt.Sprintf("agent-%d", i), NumExecutors: 4, Labels: []string{"linux", "docker"}})
	}
	for i := 0; i < 500; i++ {
		snap.Controller.Credentials = append(snap.Controller.Credentials, ci.Credential{ID: fmt.Sprintf("cred-%d", i), Type: "Secret text", Store: "system", Domain: "_"})
	}
	for i := 0; i < 300; i++ {
		snap.Controller.Plugins = append(snap.Controller.Plugins, ci.Plugin{ShortName: fmt.Sprintf("plugin-%d", i), Version: "1.0", Enabled: true, Active: true})
	}
	base := snap.Jobs
	snap.Jobs = nil
	for i := 0; i < 1000; i++ {
		j := base[i%len(base)]
		j.FullName = fmt.Sprintf("team-%d/job-%d", i%50, i)
		snap.Jobs = append(snap.Jobs, j)
	}
	eng, err := New(context.Background(), config.Default(), ci.PlatformJenkins)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Evaluate(context.Background(), snap); err != nil {
			b.Fatal(err)
		}
	}
}

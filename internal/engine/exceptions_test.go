package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/config"
)

var exceptionNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func failing(check, resource, severity string) Finding {
	return Finding{CheckID: check, Resource: resource, Severity: severity, Status: StatusFail}
}

func TestExceptionsAcceptMatchingFindingsOnly(t *testing.T) {
	findings := []Finding{
		failing("CIS-2.3.5", "platform/legacy-build", "MEDIUM"),
		failing("CIS-2.3.5", "platform/payments", "MEDIUM"),
		failing("CIS-2.3.1", "platform/legacy-build", "HIGH"),
		failing("CIS-2.3.5", "platform/legacy/nested", "MEDIUM"),
		failing("CIS-2.3.5", "Platform/legacy-build", "MEDIUM"),
		{CheckID: "CIS-2.3.5", Resource: "platform/legacy-ui", Severity: "MEDIUM", Status: StatusPass},
	}
	warnings := applyExceptions(findings, []config.Exception{{
		Control: "cis-2.3.5", Resources: []string{"platform/legacy-*"},
		Reason: "vendor job", Owner: "platform", Expires: "2027-03-31",
	}}, exceptionNow)

	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if w := findings[0].Waiver; w == nil || w.Reason != "vendor job" || w.Owner != "platform" || w.Expires != "2027-03-31" {
		t.Errorf("legacy-build CIS-2.3.5 waiver = %+v, want the exception", w)
	}
	if findings[1].Waiver != nil {
		t.Error("platform/payments does not match platform/legacy-* and must not be accepted")
	}
	if findings[2].Waiver != nil {
		t.Error("another control on the same job must not be accepted")
	}
	if findings[3].Waiver != nil {
		t.Error("* does not cross a folder boundary")
	}
	if findings[4].Waiver != nil {
		t.Error("Jenkins names are case-sensitive: Platform is another folder")
	}
	if findings[5].Waiver != nil {
		t.Error("a PASS has nothing to accept")
	}
}

// The controller-scope resource is named "controller".
func TestExceptionsCanAcceptAControllerFinding(t *testing.T) {
	findings := []Finding{failing("CIS-2.2.3", InstanceResourceName, "HIGH")}
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-2.2.3", Resources: []string{"controller"}, Reason: "agents arrive in Q1", Expires: "2027-01-01",
	}}, exceptionNow)
	if findings[0].Waiver == nil {
		t.Error("an exception on the controller was not applied")
	}
}

// A lapsed exception does nothing, and says so: its findings fail the run
// again from the day after its expiry.
func TestLapsedExceptionsAreNotAppliedAndAreReported(t *testing.T) {
	findings := []Finding{failing("CIS-2.3.5", "legacy", "MEDIUM")}
	warnings := applyExceptions(findings, []config.Exception{{
		Control: "CIS-2.3.5", Resources: []string{"legacy"}, Reason: "r", Expires: "2026-09-30",
	}}, exceptionNow)
	if findings[0].Waiver != nil {
		t.Error("a lapsed exception was applied")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "lapsed on 2026-09-30") {
		t.Errorf("warnings = %v, want the lapse reported", warnings)
	}

	// The expiry day itself still counts.
	findings = []Finding{failing("CIS-2.3.5", "legacy", "MEDIUM")}
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-2.3.5", Resources: []string{"legacy"}, Reason: "r", Expires: "2026-10-01",
	}}, exceptionNow)
	if findings[0].Waiver == nil {
		t.Error("an exception expiring today must still apply today")
	}
}

// An exception that accepts nothing is a finding fixed, renamed or out of
// scope — or a typo. Either way the list is rotting, and it is said.
func TestExceptionsMatchingNothingAreReported(t *testing.T) {
	warnings := applyExceptions([]Finding{failing("CIS-2.3.5", "a", "MEDIUM")}, []config.Exception{{
		Control: "CIS-2.3.1", Resources: []string{"a"}, Reason: "r", Expires: "2027-01-01",
	}}, exceptionNow)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "accepts nothing") {
		t.Errorf("warnings = %v, want the stale exception reported", warnings)
	}
}

// The score describes the controller, and accepting a finding does not change
// the controller; what changes is whether the run fails on it.
func TestAcceptedFailuresStayInTheScoreButDoNotFailTheRun(t *testing.T) {
	findings := []Finding{failing("CIS-2.3.1", "a", "HIGH"), {CheckID: "CIS-2.1.2", Resource: "a", Severity: "HIGH", Status: StatusPass}}
	before := Compute(findings)
	applyExceptions(findings, []config.Exception{{
		Control: "CIS-2.3.1", Resources: []string{"*"}, Reason: "r", Expires: "2027-01-01",
	}}, exceptionNow)
	rep := &Report{Findings: findings, Score: Compute(findings)}

	if rep.Score.Value != before.Value || rep.Score.Failed != before.Failed || rep.Score.EarnedWeight != before.EarnedWeight {
		t.Errorf("score changed from %+v to %+v", before, rep.Score)
	}
	if rep.HasFailureAtOrAbove("high") {
		t.Error("an accepted HIGH failure still fails the run")
	}
	findings[0].Waiver = nil
	if !(&Report{Findings: findings}).HasFailureAtOrAbove("high") {
		t.Error("an unaccepted HIGH failure must fail the run")
	}
}

// Evaluate applies the configured exceptions after scoring.
func TestEvaluateAppliesExceptions(t *testing.T) {
	cfg := config.Default()
	cfg.Exceptions = []config.Exception{{Control: "CIS-2.3.1", Resources: []string{"legacy-build"}, Reason: "r", Expires: "2027-01-01"}}
	eng, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err != nil {
		t.Fatal(err)
	}
	eng.now = func() time.Time { return exceptionNow }
	rep, err := eng.Evaluate(context.Background(), hardenedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.CheckID == "CIS-2.3.1" && f.Resource == "legacy-build" {
			if f.Status != StatusFail || f.Waiver == nil {
				t.Errorf("legacy-build CIS-2.3.1 = %s with waiver %+v, want FAIL accepted", f.Status, f.Waiver)
			}
			return
		}
	}
	t.Fatal("no CIS-2.3.1 finding for legacy-build")
}

// An exception for CIS-2.3.55 instead of CIS-2.3.5 accepts nothing. It fails
// safe — the finding still fails the run — but the only clue was a warning
// that it matched nothing, next to an exception plainly visible in the file.
// It is refused at startup, as an include or exclude naming no control is,
// with the same tolerance for case and padding.
func TestExceptionNamingNoControlIsRefused(t *testing.T) {
	cfg := config.Default()
	cfg.Exceptions = []config.Exception{{Control: "CIS-2.3.55", Resources: []string{"*"}, Reason: "typo", Expires: "2099-01-01"}}
	_, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err == nil || !strings.Contains(err.Error(), "CIS-2.3.55 (exceptions[0])") {
		t.Fatalf("err = %v, want the unknown control named with its exceptions[0] index", err)
	}

	cfg.Exceptions = []config.Exception{{Control: "  cis-2.3.5 ", Resources: []string{"legacy-build"}, Reason: "vendor job", Expires: "2099-01-01"}}
	eng, err := New(context.Background(), cfg, ci.PlatformJenkins)
	if err != nil {
		t.Fatalf("a valid ID with different case and padding was rejected: %v", err)
	}
	// And, accepted at startup, it applies: the same tolerance on both sides.
	snap := hardenedSnapshot()
	snap.Jobs[1].UnauthenticatedTriggers = []string{"authToken"}
	snap.Jobs[1].TriggersKnown = true
	eng.now = func() time.Time { return exceptionNow }
	rep, err := eng.Evaluate(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExceptionWarnings) != 0 {
		t.Errorf("a padded control ID accepted at startup must match: %v", rep.ExceptionWarnings)
	}
}

package engine

import "testing"

func finding(severity string, status Status) Finding {
	return Finding{Severity: severity, Status: status, CheckID: "CIS-" + severity + "-" + string(status)}
}

func TestComputeWeightsBySeverity(t *testing.T) {
	// HIGH=3, MEDIUM=2, LOW=1. One HIGH pass and one MEDIUM fail gives 3 of 5.
	score := Compute([]Finding{
		finding("HIGH", StatusPass),
		finding("MEDIUM", StatusFail),
	})

	if score.EarnedWeight != 3 || score.TotalWeight != 5 {
		t.Errorf("weights = %d/%d, want 3/5", score.EarnedWeight, score.TotalWeight)
	}
	if score.Value != 60 {
		t.Errorf("score = %d, want 60", score.Value)
	}
}

// MANUAL and NA must not move the score in either direction: an instance is
// neither punished nor credited for a question its API cannot answer.
func TestManualAndNotApplicableAreExcludedFromScore(t *testing.T) {
	base := Compute([]Finding{finding("HIGH", StatusPass), finding("HIGH", StatusFail)})

	withUnknowns := Compute([]Finding{
		finding("HIGH", StatusPass),
		finding("HIGH", StatusFail),
		finding("HIGH", StatusManual),
		finding("HIGH", StatusNA),
	})

	if base.Value != withUnknowns.Value {
		t.Errorf("score changed from %d to %d when MANUAL and NA findings were added", base.Value, withUnknowns.Value)
	}
	if withUnknowns.Manual != 1 || withUnknowns.NotApplicable != 1 {
		t.Errorf("manual=%d na=%d, want 1 and 1", withUnknowns.Manual, withUnknowns.NotApplicable)
	}
}

// A run where nothing could be decided must not look like a perfect score.
func TestNothingDecidableScoresZeroNotOneHundred(t *testing.T) {
	score := Compute([]Finding{finding("HIGH", StatusManual), finding("LOW", StatusNA)})
	if score.Value != 0 {
		t.Errorf("score = %d, want 0 when no control was decidable", score.Value)
	}
	if score.TotalWeight != 0 {
		t.Errorf("totalWeight = %d, want 0", score.TotalWeight)
	}
}

func TestAllPassingScoresOneHundred(t *testing.T) {
	score := Compute([]Finding{
		finding("HIGH", StatusPass),
		finding("MEDIUM", StatusPass),
		finding("LOW", StatusPass),
	})
	if score.Value != 100 {
		t.Errorf("score = %d, want 100", score.Value)
	}
}

func TestHasFailureAtOrAboveSeverity(t *testing.T) {
	report := &Report{Findings: []Finding{
		finding("MEDIUM", StatusFail),
		finding("HIGH", StatusPass),
	}}

	if report.HasFailureAtOrAbove("high") {
		t.Error("a MEDIUM failure must not trip a HIGH threshold")
	}
	if !report.HasFailureAtOrAbove("medium") {
		t.Error("a MEDIUM failure must trip a MEDIUM threshold")
	}
	if !report.HasFailureAtOrAbove("low") {
		t.Error("a MEDIUM failure must trip a LOW threshold")
	}
}

func TestSortFindingsPutsFailuresFirst(t *testing.T) {
	findings := []Finding{
		{CheckID: "a", Severity: "LOW", Status: StatusPass, CISID: "1.1.1"},
		{CheckID: "b", Severity: "LOW", Status: StatusFail, CISID: "1.1.2"},
		{CheckID: "c", Severity: "HIGH", Status: StatusFail, CISID: "1.1.3"},
		{CheckID: "d", Severity: "LOW", Status: StatusManual, CISID: "1.1.4"},
	}
	sortFindings(findings)

	want := []string{"c", "b", "d", "a"}
	for i, id := range want {
		if findings[i].CheckID != id {
			t.Fatalf("order = %s..., want %v", findings[i].CheckID, want)
		}
	}
}

// Findings of equal status and severity are ordered by benchmark number, which
// is numeric per component. A lexical comparison would sort CIS-1.1.15 ahead of
// CIS-1.1.3 and make the report read as if the benchmark were out of order.
func TestSortFindingsOrdersBenchmarkNumbersNumerically(t *testing.T) {
	findings := []Finding{
		{CheckID: "CIS-1.1.15", Severity: "HIGH", Status: StatusFail, CISID: "1.1.15"},
		{CheckID: "CIS-1.1.3", Severity: "HIGH", Status: StatusFail, CISID: "1.1.3"},
		{CheckID: "CIS-1.1.9", Severity: "HIGH", Status: StatusFail, CISID: "1.1.9"},
		{CheckID: "CIS-1.1.16", Severity: "HIGH", Status: StatusFail, CISID: "1.1.16"},
	}
	sortFindings(findings)

	want := []string{"CIS-1.1.3", "CIS-1.1.9", "CIS-1.1.15", "CIS-1.1.16"}
	for i, id := range want {
		if findings[i].CheckID != id {
			t.Fatalf("order[%d] = %s, want %v", i, findings[i].CheckID, want)
		}
	}
}

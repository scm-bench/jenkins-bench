package engine

import (
	"math"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/checks"
)

// Score summarises a report as a single 0-100 number plus the counts behind it.
//
// The formula is deliberately the simple one: severity-weighted passes over
// severity-weighted applicable checks. MANUAL and NA are excluded from both
// sides, so an instance is never punished for a question its API cannot answer,
// and never credited for one either.
type Score struct {
	// Value is the weighted percentage of applicable checks that passed.
	Value int `json:"value"`
	// EarnedWeight and TotalWeight are the numerator and denominator.
	EarnedWeight int `json:"earnedWeight"`
	TotalWeight  int `json:"totalWeight"`

	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Manual        int `json:"manual"`
	NotApplicable int `json:"notApplicable"`
	Total         int `json:"total"`

	// BySeverity breaks the failures down, which is what decides whether a
	// score is acceptable in practice.
	BySeverity map[string]SeverityCount `json:"bySeverity"`
}

// SeverityCount is the per-severity breakdown.
type SeverityCount struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Manual int `json:"manual"`
}

// Compute derives the score from a set of findings.
func Compute(findings []Finding) Score {
	score := Score{
		Total:      len(findings),
		BySeverity: map[string]SeverityCount{},
	}

	for _, f := range findings {
		severity := strings.ToUpper(f.Severity)
		weight := checks.Weight(severity)
		counts := score.BySeverity[severity]

		switch f.Status {
		case StatusPass:
			score.Passed++
			counts.Passed++
			score.EarnedWeight += weight
			score.TotalWeight += weight
		case StatusFail:
			score.Failed++
			counts.Failed++
			score.TotalWeight += weight
		case StatusManual:
			score.Manual++
			counts.Manual++
		case StatusNA:
			score.NotApplicable++
		}
		score.BySeverity[severity] = counts
	}

	if score.TotalWeight == 0 {
		// Nothing was decidable. Reporting 100 would read as a clean bill of
		// health, so an empty denominator scores zero and the MANUAL count
		// alongside it explains why.
		score.Value = 0
		return score
	}
	score.Value = int(math.Round(float64(score.EarnedWeight) / float64(score.TotalWeight) * 100))
	return score
}

// HasFailureAtOrAbove reports whether any finding failed at or above the given
// severity. It backs the --fail-on exit code.
func (r *Report) HasFailureAtOrAbove(severity string) bool {
	threshold := checks.Weight(severity)
	for _, f := range r.Findings {
		if f.Status == StatusFail && checks.Weight(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

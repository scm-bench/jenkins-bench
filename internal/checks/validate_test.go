package checks

import (
	"strings"
	"testing"
)

// valid returns metadata that passes, so each case below changes exactly one
// thing and the failure names the field that broke.
func valid() Metadata {
	return Metadata{
		ID:          "CIS-2.1.6",
		CISID:       "2.1.6",
		Package:     "scmbench.rules.cis_2_1_6",
		Scope:       ScopeController,
		Severity:    SeverityHigh,
		Platforms:   []string{"jenkins"},
		Automated:   true,
		Title:       "Ensure users must authenticate to access the build environment",
		Remediation: "Manage Jenkins -> Security: remove every Anonymous permission.",
		FixSummary:  "Remove all Anonymous permissions at Manage Jenkins -> Security.",
	}
}

// The generic metadata schema no longer enumerates legal scopes — which domain
// words are allowed is a question about a domain. That makes this the only
// thing standing between a typo and a control that is silently never evaluated
// against anything, because the engine dispatches on scope and an unrecognised
// one matches no branch.
func TestValidateRejectsAScopeFromAnotherDomain(t *testing.T) {
	for _, scope := range []string{"repository", "organization", "Controller", "jobs", ""} {
		m := valid()
		m.Scope = scope
		c := Check{Metadata: m}
		err := c.validate()
		if err == nil {
			t.Errorf("scope %q was accepted", scope)
			continue
		}
		if !strings.Contains(err.Error(), "scope") {
			t.Errorf("scope %q: error should name the field, got %v", scope, err)
		}
	}
}

func TestValidateAcceptsThisDomainsScopes(t *testing.T) {
	for _, scope := range []string{ScopeController, ScopeJob} {
		m := valid()
		m.Scope = scope
		c := Check{Metadata: m}
		if err := c.validate(); err != nil {
			t.Errorf("scope %q was rejected: %v", scope, err)
		}
	}
}

func TestValidateRequiresEveryFieldAReportPrints(t *testing.T) {
	tests := []struct {
		field  string
		mutate func(*Metadata)
	}{
		{"id", func(m *Metadata) { m.ID = "" }},
		{"package", func(m *Metadata) { m.Package = "" }},
		{"title", func(m *Metadata) { m.Title = "" }},
		// Both lengths of remediation are required. fixSummary prints in the
		// findings table and remediation in its own section, so a control
		// missing either is one a reader cannot act on from where they are.
		{"remediation", func(m *Metadata) { m.Remediation = "" }},
		{"fixSummary", func(m *Metadata) { m.FixSummary = "" }},
		{"severity", func(m *Metadata) { m.Severity = "CRITICAL" }},
		{"platform", func(m *Metadata) { m.Platforms = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			m := valid()
			tt.mutate(&m)
			c := Check{Metadata: m}
			if err := c.validate(); err == nil {
				t.Errorf("metadata missing %s was accepted", tt.field)
			}
		})
	}
}

// Severity decides a control's weight in the score, and Weight() falls back to
// LOW for anything it does not recognise. Accepting a misspelled severity would
// therefore quietly reweight the control rather than fail.
func TestValidateAcceptsSeverityInAnyCase(t *testing.T) {
	for _, s := range []string{"HIGH", "high", "Medium", "low"} {
		m := valid()
		m.Severity = s
		c := Check{Metadata: m}
		if err := c.validate(); err != nil {
			t.Errorf("severity %q was rejected: %v", s, err)
		}
	}
}

func TestLessCISIDHandlesNonNumericComponents(t *testing.T) {
	// Not every identifier is dotted digits, and the comparison must stay a
	// total order rather than panicking or reporting a < b and b < a.
	pairs := [][2]string{{"2.1.6", "2.1.6a"}, {"a", "b"}, {"", "1"}, {"1.x", "1.y"}}
	for _, p := range pairs {
		a, b := p[0], p[1]
		if LessCISID(a, b) && LessCISID(b, a) {
			t.Errorf("LessCISID is inconsistent for %q and %q", a, b)
		}
	}
}

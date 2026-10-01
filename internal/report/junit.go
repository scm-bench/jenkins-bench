package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// JUnit XML, for the CI systems that draw test results natively — Jenkins'
// own JUnit publisher first among them, Azure Pipelines' PublishTestResults,
// GitLab's test report. None of them reads SARIF without an extension, and all
// of them read this: a controller audited from a Jenkins pipeline gets its
// result in the build's own test view, with no plugin.
//
// One test suite per control and one test case per resource it was evaluated
// against, so a CI's test view groups the way the report does: by control,
// with the jobs underneath. A FAIL is a failure; MANUAL, NA and an accepted
// failure are skipped, each with the reason in the message, so the totals add
// up to every finding and nothing is silently dropped.

type junitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Properties *junitProperties `xml:"properties,omitempty"`
	Suites     []junitTestSuite `xml:"testsuite"`
}

type junitProperties struct {
	Property []junitProperty `xml:"property"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Skipped  int             `xml:"skipped,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(w io.Writer, rep *engine.Report, opts Options) error {
	byControl := map[string]*junitTestSuite{}
	var order []string
	root := junitTestSuites{Name: sarifToolName}

	for _, f := range rep.Findings {
		suite, ok := byControl[f.CheckID]
		if !ok {
			suite = &junitTestSuite{Name: f.CheckID + ": " + f.Title}
			byControl[f.CheckID] = suite
			order = append(order, f.CheckID)
		}
		tc := junitTestCase{Name: f.Resource, ClassName: f.CheckID}
		switch {
		case f.Status == engine.StatusFail && f.Waiver == nil:
			tc.Failure = &junitFailure{
				Message: f.Details,
				Type:    strings.ToUpper(f.Severity),
				Text:    failureText(f),
			}
			suite.Failures++
		case f.Waiver != nil:
			tc.Skipped = &junitSkipped{Message: fmt.Sprintf("%s, %s", f.Status, acceptedNote(f.Waiver))}
			suite.Skipped++
		case f.Status == engine.StatusManual:
			tc.Skipped = &junitSkipped{Message: "MANUAL: " + f.Details}
			suite.Skipped++
		case f.Status == engine.StatusNA:
			tc.Skipped = &junitSkipped{Message: "not applicable: " + f.Details}
			suite.Skipped++
		}
		suite.Tests++
		suite.Cases = append(suite.Cases, tc)
	}

	sort.Strings(order)
	for _, id := range order {
		suite := byControl[id]
		root.Suites = append(root.Suites, *suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
		root.Skipped += suite.Skipped
	}
	root.Properties = &junitProperties{Property: []junitProperty{
		{Name: "score", Value: fmt.Sprintf("%d", rep.Score.Value)},
		{Name: "baseUrl", Value: rep.Metadata.BaseURL},
		{Name: "platform", Value: rep.Metadata.Platform},
		{Name: "toolVersion", Value: opts.ToolVersion},
	}}

	// A scan that missed jobs must not render as a clean test run: the jobs
	// it never saw have no test case to fail, so the run carries failing
	// cases of its own — one per container it could not list, one for a scan
	// that judged no job at all, one per policy that failed to evaluate.
	if scan := scanCases(rep); len(scan) > 0 {
		suite := junitTestSuite{Name: "scan", Cases: scan, Tests: len(scan), Failures: len(scan)}
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// scanCases are the failing cases a run carries for what it could not do.
func scanCases(rep *engine.Report) []junitTestCase {
	var cases []junitTestCase
	if !rep.Coverage.Complete {
		if len(rep.Coverage.Unlisted) == 0 {
			cases = append(cases, junitTestCase{
				Name: "job list", ClassName: "scan.coverage",
				Failure: &junitFailure{Message: "the snapshot does not record its job list as complete", Type: "ERROR"},
			})
		}
		for _, container := range rep.Coverage.Unlisted {
			cases = append(cases, junitTestCase{
				Name: container, ClassName: "scan.coverage",
				Failure: &junitFailure{Message: "the jobs in this folder could not be listed", Type: "ERROR"},
			})
		}
	}
	if rep.Coverage.NoJobsAudited() {
		cases = append(cases, junitTestCase{
			Name: "jobs", ClassName: "scan.coverage",
			Failure: &junitFailure{Message: "no job was evaluated; a token without Job/Read is shown an empty job list", Type: "ERROR"},
		})
	}
	for _, e := range rep.Errors {
		cases = append(cases, junitTestCase{
			Name: "policy evaluation", ClassName: "scan.policy",
			Failure: &junitFailure{Message: e, Type: "ERROR"},
		})
	}
	return cases
}

// failureText is what a CI shows when the failure is opened: the finding, the
// values behind it, and how to fix it.
func failureText(f engine.Finding) string {
	var b strings.Builder
	b.WriteString(f.Details)
	for _, e := range f.Evidence {
		b.WriteString("\n  · " + e)
	}
	if f.Remediation != "" {
		b.WriteString("\n\nFix: " + f.Remediation)
	}
	return b.String()
}

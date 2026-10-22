package report

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// failAfter is a writer that accepts n bytes and then refuses, the way a full
// disk or a closed pipe does partway through a report.
type failAfter struct{ n int }

var errRefused = errors.New("write refused")

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		n := f.n
		f.n = 0
		return n, errRefused
	}
	f.n -= len(p)
	return len(p), nil
}

func TestJUnitSurfacesWriteErrors(t *testing.T) {
	for _, n := range []int{0, len(xml.Header), len(xml.Header) + 50} {
		err := Write(&failAfter{n: n}, sample(), Options{Format: FormatJUnit})
		if !errors.Is(err, errRefused) {
			t.Errorf("after %d bytes: Write() = %v, want the writer's error", n, err)
		}
	}
}

func TestJUnitFailureTextCarriesTheEvidence(t *testing.T) {
	rep := sample()
	rep.Findings[0].Evidence = []string{"anonymous: Overall/Read"}
	_, raw := junitOf(t, rep)
	if !strings.Contains(raw, "· anonymous: Overall/Read") {
		t.Errorf("the failure text lost its evidence:\n%s", raw)
	}
}

func TestSARIFCarriesPolicyErrorsAsNotifications(t *testing.T) {
	rep := sample()
	rep.Errors = []string{"CIS-2.1.6 on controller: policy produced no result"}
	doc := sarifOf(t, rep)
	found := false
	for _, n := range doc.Runs[0].Invocations[0].ToolExecutionNotifications {
		if n.Message.Text == rep.Errors[0] {
			found = true
		}
	}
	if !found {
		t.Errorf("the policy error is not among the notifications")
	}
}

// A snapshot written before the platform was recorded still gets a location
// under the one platform this bench audits.
func TestSARIFDefaultsAMissingPlatform(t *testing.T) {
	rep := sample()
	rep.Metadata.Platform = ""
	doc := sarifOf(t, rep)
	uri := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.HasPrefix(uri, "jenkins/") {
		t.Errorf("uri = %q, want it under jenkins/", uri)
	}
}

func TestSARIFLevelsFollowSeverity(t *testing.T) {
	for sev, want := range map[string]string{"HIGH": "error", "medium": "warning", "LOW": "note", "": "note"} {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
	// The cap keeps real failures by severity, a LOW one above anything that
	// only needs a person.
	if low, manual := resultRank(sarifResult{Level: "note"}), resultRank(sarifResult{RuleID: "X" + manualRuleSuffix}); low <= manual {
		t.Errorf("rank(note) = %d, rank(manual) = %d; a LOW failure must outrank a manual result", low, manual)
	}
}

func TestLessGroupOrdersBySeverityBenchmarkSpreadThenText(t *testing.T) {
	g := func(sev, cis string, n int, details string) findingGroup {
		return findingGroup{rep: engine.Finding{Severity: sev, CISID: cis}, details: details, resources: make([]string, n)}
	}
	cases := []struct {
		name string
		x, y findingGroup
	}{
		{"severity", g("HIGH", "2.9", 1, "z"), g("LOW", "1.1", 9, "a")},
		{"benchmark number", g("HIGH", "1.1.9", 1, "z"), g("HIGH", "1.1.11", 9, "a")},
		{"spread", g("HIGH", "1.1", 3, "z"), g("HIGH", "1.1", 2, "a")},
		{"details", g("HIGH", "1.1", 2, "a"), g("HIGH", "1.1", 2, "b")},
	}
	for _, tc := range cases {
		if !lessGroup(tc.x, tc.y) || lessGroup(tc.y, tc.x) {
			t.Errorf("%s: want x strictly before y", tc.name)
		}
	}
}

func TestLessTallyPutsTheWorstResourceFirst(t *testing.T) {
	cases := []struct {
		name string
		x, y resourceTally
	}{
		{"failed", resourceTally{name: "z", failed: 2}, resourceTally{name: "a", failed: 1, unread: 9}},
		{"unread", resourceTally{name: "z", unread: 2}, resourceTally{name: "a", unread: 1, manual: 9}},
		{"manual", resourceTally{name: "z", manual: 2}, resourceTally{name: "a", manual: 1}},
		{"name", resourceTally{name: "a"}, resourceTally{name: "b"}},
	}
	for _, tc := range cases {
		if !lessTally(tc.x, tc.y) || lessTally(tc.y, tc.x) {
			t.Errorf("%s: want x strictly before y", tc.name)
		}
	}
}

func TestDetailFiltersAcceptABareBenchmarkNumberAndAll(t *testing.T) {
	findings := sample().Findings
	got, err := parseDetailFilters([]string{"", "ALL", "2.1.6"}, findings)
	if err != nil {
		t.Fatal(err)
	}
	if !got.controls["CIS-2.1.6"] || len(got.controls) != 1 {
		t.Errorf("controls = %v, want only CIS-2.1.6", got.controls)
	}
}

func TestFixLineFallsBackToTheFirstSentence(t *testing.T) {
	cases := map[string]string{
		"Open Security. Then remove Anonymous.": "Open Security.",
		"Open Security":                         "Open Security",
	}
	for remediation, want := range cases {
		if got := fixLine(engine.Finding{Remediation: remediation}); got != want {
			t.Errorf("fixLine(%q) = %q, want %q", remediation, got, want)
		}
	}
}

// The header sheds the timestamp, then the URL, as the terminal narrows; the
// summary drops its counts to a second line. Nothing is lost on the way.
func TestHeaderAndSummaryGiveWayOnANarrowTerminal(t *testing.T) {
	rep := sample()
	head := "jenkins-bench 0.1.0  ·  https://jenkins.invalid"
	for _, width := range []int{len(head) + 5, len(head) - 5} {
		var buf bytes.Buffer
		writeHeader(&buf, rep, painter{}, width)
		out := buf.String()
		for _, want := range []string{"0.1.0", "https://jenkins.invalid", "scanned 2026-08-14"} {
			if !strings.Contains(out, want) {
				t.Errorf("width %d: header lost %q:\n%s", width, want, out)
			}
		}
		if lines := strings.Count(out, "\n"); width < len(head) && lines != 3 {
			t.Errorf("width %d: header is %d lines, want 3", width, lines)
		}
	}

	var buf bytes.Buffer
	writeSummary(&buf, rep, painter{}, 30)
	lines := strings.Split(buf.String(), "\n")
	if len(lines) < 3 || !strings.HasPrefix(lines[1], "SCORE") || !strings.Contains(lines[2], "passed") {
		t.Errorf("a narrow summary should put the counts on their own line:\n%s", buf.String())
	}
}

// With no width given, the renderer asks the environment.
func TestTableWidthDefaultsToTheEnvironment(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	var buf bytes.Buffer
	if err := Write(&buf, sample(), Options{Format: FormatTable}); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if n := len([]rune(l)); n > 60 && !strings.Contains(l, "https://") {
			t.Errorf("line of %d columns under COLUMNS=60: %q", n, l)
		}
	}
}

// Colour paints the words and never the layout: with it on, every word that
// was there without it is still there.
func TestColourDoesNotChangeTheWords(t *testing.T) {
	rep := sample()
	rep.Errors = []string{"CIS-2.3.1 on legacy-build: policy evaluation failed"}
	rep.Metadata.Warnings = []string{"(GET /pluginManager 403) the plugin list could not be read"}
	for _, details := range []bool{false, true} {
		var plain, coloured bytes.Buffer
		if err := Write(&plain, rep, Options{Format: FormatTable, Width: 100, Details: details}); err != nil {
			t.Fatal(err)
		}
		if err := Write(&coloured, rep, Options{Format: FormatTable, Width: 100, Details: details, Color: true}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(coloured.String(), "\x1b[") {
			t.Fatalf("details=%v: Color produced no escapes", details)
		}
		if got := stripANSI(coloured.String()); got != plain.String() {
			t.Errorf("details=%v: colour changed the text\n--- plain\n%s\n--- coloured, stripped\n%s", details, plain.String(), got)
		}
		if !strings.Contains(plain.String(), "Policy errors") || !strings.Contains(plain.String(), rep.Errors[0]) {
			t.Errorf("details=%v: the policy error is missing:\n%s", details, plain.String())
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestDimParensSkipsEmptySegments(t *testing.T) {
	got, depth := dimParens(painter{enabled: true}, "(a)(b) c", 0)
	if depth != 0 || stripANSI(got) != "(a)(b) c" {
		t.Errorf("dimParens = %q, depth %d", got, depth)
	}
}

// A long resource name leaves the reason no room beside it, so the reason
// starts on its own line; long evidence wraps under its bullet.
func TestFindingLinesWrapOnANarrowTerminal(t *testing.T) {
	rep := sample()
	f := &rep.Findings[2] // FAIL on legacy-build
	f.Resource = "platform/team-a/services/a-job-name-long-enough-to-crowd-the-line"
	f.Evidence = []string{"one piece of evidence long enough that it has to wrap onto a second line at this width"}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 70}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, f.Resource+"  CIS-2.3.1 HIGH:\n"+contIndent+"one sentence") {
		t.Errorf("the reason should start on its own line under a long head:\n%s", out)
	}
	if !strings.Contains(out, contIndent+"· one piece") || !strings.Contains(out, contIndent+"  ") {
		t.Errorf("long evidence should wrap under its bullet:\n%s", out)
	}
}

// Evidence rides in the finding's own cell in the per-resource layout.
func TestDetailsCellCarriesTheEvidence(t *testing.T) {
	rep := sample()
	rep.Findings[0].Evidence = []string{"anonymous: Overall/Read"}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 120, Details: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "· anonymous: Overall/Read") {
		t.Errorf("evidence missing from the details cell:\n%s", buf.String())
	}
}

// A job-scope control failing on every job it was evaluated against is one
// folder-level setting, and the rules index says so — beside the link when
// the control has one, on its own line when it does not.
func TestRulesIndexSuggestsAFolderLevelFix(t *testing.T) {
	for _, withRef := range []bool{true, false} {
		rep := sample()
		var findings []engine.Finding
		for _, job := range []string{"a", "b", "c"} {
			f := finding("CIS-2.3.9", job, engine.ResourceJob, engine.StatusFail, "MEDIUM")
			f.Remediation = "Folder settings -> Pipeline: set the library. Then rerun."
			if !withRef {
				f.References = nil
			}
			findings = append(findings, f)
		}
		rep.Findings = append(rep.Findings, findings...)
		rep.Score = engine.Compute(rep.Findings)
		var buf bytes.Buffer
		if err := Write(&buf, rep, Options{Format: FormatTable, Width: 100}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "failing on all 3 jobs") {
			t.Errorf("withRef=%v: no folder-level hint:\n%s", withRef, buf.String())
		}
	}
}

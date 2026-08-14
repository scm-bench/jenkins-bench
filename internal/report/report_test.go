package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/engine"
)

func finding(id, resource, resourceType string, status engine.Status, severity string) engine.Finding {
	return engine.Finding{
		CheckID:      id,
		CISID:        strings.TrimPrefix(id, "CIS-"),
		Title:        "Ensure users must authenticate to access the build environment",
		Severity:     severity,
		Resource:     resource,
		ResourceType: resourceType,
		Status:       status,
		Details:      "one sentence about this resource",
		Remediation:  "Manage Jenkins -> Security: remove every Anonymous permission.",
		FixSummary:   "Remove all Anonymous permissions at Manage Jenkins -> Security.",
		Automated:    true,
		References:   []string{"https://www.jenkins.io/doc/book/security/managing-security/"},
	}
}

func sample() *engine.Report {
	rep := &engine.Report{
		Metadata: ci.Metadata{
			Tool:        "jenkins-bench",
			ToolVersion: "0.1.0",
			Platform:    ci.PlatformJenkins,
			BaseURL:     "https://jenkins.invalid",
			GeneratedAt: time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC),
			Warnings:    []string{"this token cannot read the plugin list"},
		},
		Findings: []engine.Finding{
			finding("CIS-2.1.6", "controller", engine.ResourceController, engine.StatusFail, "HIGH"),
			finding("CIS-2.3.1", "platform/api-service", engine.ResourceJob, engine.StatusPass, "HIGH"),
			finding("CIS-2.3.1", "legacy-build", engine.ResourceJob, engine.StatusFail, "HIGH"),
			finding("CIS-2.3.5", "legacy-build", engine.ResourceJob, engine.StatusManual, "MEDIUM"),
			finding("CIS-2.2.3", "disabled-job", engine.ResourceJob, engine.StatusNA, "LOW"),
		},
	}
	rep.Score = engine.Compute(rep.Findings)
	return rep
}

func render(t *testing.T, format string, opts Options) string {
	t.Helper()
	opts.Format = format
	if opts.Width == 0 {
		opts.Width = 100
	}
	var buf bytes.Buffer
	if err := Write(&buf, sample(), opts); err != nil {
		t.Fatalf("Write(%s): %v", format, err)
	}
	return buf.String()
}

func TestFormatsAreAllWritable(t *testing.T) {
	for _, f := range Formats() {
		out := render(t, f, Options{})
		if strings.TrimSpace(out) == "" {
			t.Errorf("format %q produced nothing", f)
		}
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), Options{Format: "yaml"}); err == nil {
		t.Error("an unknown format should be an error, not silently the default")
	}
}

// MANUAL must be visible in every format. A report that shows failures and
// hides what could not be read is the same lie as reporting PASS.
func TestManualIsVisibleInEveryFormat(t *testing.T) {
	for _, f := range Formats() {
		out := render(t, f, Options{})
		if !strings.Contains(strings.ToUpper(out), "MANUAL") {
			t.Errorf("format %q does not mention MANUAL:\n%s", f, out)
		}
	}
}

func TestTableShowsTheScoreArithmetic(t *testing.T) {
	out := render(t, FormatTable, Options{})
	// Printing the arithmetic is what makes the number checkable rather than
	// something to be trusted.
	for _, want := range []string{"SCORE", "weighted", "HIGH=3", "MEDIUM=2", "LOW=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the score line is missing %q:\n%s", want, out)
		}
	}
}

func TestTableNamesTheControllerResource(t *testing.T) {
	out := render(t, FormatTable, Options{})
	// The failing record leads with the resource, and the instance is named
	// by the word the engine uses everywhere else.
	if !strings.Contains(out, engine.InstanceResourceName+"  CIS-2.1.6") {
		t.Errorf("the controller's failure should lead with its name:\n%s", out)
	}
}

func TestTableCarriesRemediation(t *testing.T) {
	out := render(t, FormatTable, Options{})
	if !strings.Contains(out, "Manage Jenkins") {
		t.Errorf("a failing control's fix should name a place to act:\n%s", out)
	}
}

func TestNoRemediationsDropsTheFixes(t *testing.T) {
	with := render(t, FormatTable, Options{})
	without := render(t, FormatTable, Options{NoRemediations: true})
	if len(without) >= len(with) {
		t.Error("--no-remediations should shorten the report")
	}
	if strings.Contains(without, "fix:") {
		t.Error("the inline fixes should be gone")
	}
	if strings.Contains(without, "Rules") {
		t.Error("the rules index should be gone")
	}
}

func TestJSONCarriesEveryFinding(t *testing.T) {
	out := render(t, FormatJSON, Options{})

	var decoded struct {
		Metadata ci.Metadata      `json:"metadata"`
		Findings []engine.Finding `json:"findings"`
		Score    engine.Score     `json:"score"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json output is not valid JSON: %v\n%s", err, out)
	}
	if len(decoded.Findings) != 5 {
		t.Errorf("findings = %d, want all 5", len(decoded.Findings))
	}
	if decoded.Metadata.Platform != ci.PlatformJenkins {
		t.Errorf("metadata.platform = %q", decoded.Metadata.Platform)
	}
	// The snapshot metadata is what tells a later reader which controller and
	// which token produced this.
	if len(decoded.Metadata.Warnings) == 0 {
		t.Error("json should carry the capture warnings")
	}
	for _, f := range decoded.Findings {
		if f.Status == "" || f.Details == "" {
			t.Errorf("finding %+v is missing its verdict or details", f)
		}
	}
}

func TestSARIFIsWellFormed(t *testing.T) {
	out := render(t, FormatSARIF, Options{})

	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif output is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "jenkins-bench" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("sarif carries no rules")
	}
	if len(run.Results) == 0 {
		t.Fatal("sarif carries no results")
	}
	for _, r := range run.Results {
		// The fingerprint key is family-wide: it is a format identifier, not a
		// tool name, so a consumer can match a finding across runs and across
		// benches.
		if r.PartialFingerprints["scmBenchFindingV1"] == "" {
			t.Errorf("result %s carries no scmBenchFindingV1 fingerprint", r.RuleID)
		}
	}
}

// A fingerprint that changes between runs makes every finding look new.
func TestSARIFFingerprintsAreStable(t *testing.T) {
	first := render(t, FormatSARIF, Options{})
	second := render(t, FormatSARIF, Options{})
	if first != second {
		t.Error("two renderings of the same report differ")
	}
}

func TestShowPassedIncludesPassingControls(t *testing.T) {
	out := render(t, FormatTable, Options{ShowPassed: true})
	if !strings.Contains(out, "passed") && !strings.Contains(out, "PASS") {
		t.Errorf("--show-passed should surface passing controls:\n%s", out)
	}
}

// A report with nothing in it still has to say so, rather than printing an
// empty frame.
func TestEmptyReportStillRenders(t *testing.T) {
	empty := &engine.Report{Metadata: ci.Metadata{Tool: "jenkins-bench", Platform: ci.PlatformJenkins}}
	empty.Score = engine.Compute(nil)
	for _, f := range Formats() {
		var buf bytes.Buffer
		if err := Write(&buf, empty, Options{Format: f, Width: 100}); err != nil {
			t.Errorf("format %q on an empty report: %v", f, err)
		}
		if strings.TrimSpace(buf.String()) == "" {
			t.Errorf("format %q produced nothing for an empty report", f)
		}
	}
}

func TestScoreIsZeroNotOneHundredWhenNothingWasDecidable(t *testing.T) {
	rep := &engine.Report{Metadata: ci.Metadata{Tool: "jenkins-bench"}}
	rep.Findings = []engine.Finding{
		finding("CIS-2.1.6", "controller", engine.ResourceController, engine.StatusManual, "HIGH"),
	}
	rep.Score = engine.Compute(rep.Findings)

	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "100/100") {
		t.Errorf("an all-MANUAL report must not read as a clean bill of health:\n%s", out)
	}
	if !strings.Contains(out, "0/100") {
		t.Errorf("score should be 0:\n%s", out)
	}
}

func TestDetailsExpandsToPerResourceSections(t *testing.T) {
	overview := render(t, FormatTable, Options{})
	details := render(t, FormatTable, Options{Details: true})
	if overview == details {
		t.Error("--details should change the table body")
	}
	// The per-resource layout answers "what is wrong with *my* job", so each
	// resource with a failure or open question appears by name — and one whose
	// only findings passed does not, unless asked for.
	if !strings.Contains(details, "legacy-build") {
		t.Errorf("the details layout does not name legacy-build:\n%s", details)
	}
	if strings.Contains(details, "platform/api-service") {
		t.Errorf("a resource with only passing findings should need --show-passed:\n%s", details)
	}
	withPassed := render(t, FormatTable, Options{Details: true, ShowPassed: true})
	if !strings.Contains(withPassed, "platform/api-service") {
		t.Errorf("--show-passed should surface the passing resource:\n%s", withPassed)
	}
}

func TestDetailFiltersNarrowTheSections(t *testing.T) {
	all := render(t, FormatTable, Options{Details: true})
	one := render(t, FormatTable, Options{Details: true, DetailFilters: []string{"legacy-build"}})
	other := render(t, FormatTable, Options{Details: true, DetailFilters: []string{"platform/api-service"}})

	if len(one) >= len(all) {
		t.Error("a filter should narrow the output")
	}
	// The summary table still lists every resource — that is what a summary is
	// for. What a filter selects is whose section gets drawn, so two different
	// filters must produce two different reports.
	if one == other {
		t.Error("filtering to one resource produced the same report as filtering to another")
	}
	if !strings.Contains(one, "legacy-build") {
		t.Errorf("the named resource is missing:\n%s", one)
	}
}

func TestDetailFiltersAlsoMatchControls(t *testing.T) {
	out := render(t, FormatTable, Options{Details: true, DetailFilters: []string{"CIS-2.1.6"}})
	if !strings.Contains(out, "CIS-2.1.6") {
		t.Errorf("the named control is missing:\n%s", out)
	}
}

// A filter matching nothing is a typo, and the silent reading of it is the
// dangerous one: an empty section reads like a clean result.
func TestDetailFilterMatchingNothingIsAnError(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, sample(), Options{Format: FormatTable, Width: 100, Details: true,
		DetailFilters: []string{"no-such-job"}})
	if err == nil {
		t.Fatal("a filter matching nothing should be an error, not an empty report")
	}
	// The message has to say where to find the names that would have worked.
	for _, want := range []string{"no-such-job", "scan output", "list-checks"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error is missing %q: %v", want, err)
		}
	}
}

func TestMaxResourcesCapsTheDetailSections(t *testing.T) {
	all := render(t, FormatTable, Options{Details: true})
	capped := render(t, FormatTable, Options{Details: true, MaxResources: 1})
	if len(capped) >= len(all) {
		t.Error("MaxResources should shorten the details layout")
	}
}

func TestNoticeLeadsTheTableOutput(t *testing.T) {
	out := render(t, FormatTable, Options{Notice: "example data, not a real controller"})
	if !strings.Contains(out, "example data") {
		t.Errorf("the notice should lead the report:\n%s", out)
	}
	// The machine formats ignore it: their metadata already names the
	// controller, and a consumer of JSON is not skimming.
	jsonOut := render(t, FormatJSON, Options{Notice: "example data"})
	if strings.Contains(jsonOut, "example data") {
		t.Error("the notice reached the json output")
	}
}

func TestToolVersionIsStampedIntoSARIF(t *testing.T) {
	out := render(t, FormatSARIF, Options{ToolVersion: "0.1.0"})
	if !strings.Contains(out, "0.1.0") {
		t.Errorf("sarif should carry the tool version:\n%s", out)
	}
}

// --- the line-oriented default layout ---------------------------------------

// One record answers the whole question: which resource, which control, how
// bad, and why — the reason a reader previously had to flip to --details for.
func TestFailLineCarriesResourceControlSeverityAndDetails(t *testing.T) {
	out := render(t, FormatTable, Options{})
	if !strings.Contains(out, "legacy-build  CIS-2.3.1 HIGH: one sentence about this resource") {
		t.Errorf("the failure record is not one grep-able line:\n%s", out)
	}
}

func TestFixRidesIndentedUnderTheFinding(t *testing.T) {
	out := render(t, FormatTable, Options{})
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "legacy-build  CIS-2.3.1") {
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "    fix: ") {
				t.Errorf("the fix should be the indented line after the finding, got %q", lines[i+1])
			}
			return
		}
	}
	t.Fatalf("no failure record found:\n%s", out)
}

func TestEvidenceIsIndentedUnderTheFinding(t *testing.T) {
	rep := sample()
	rep.Findings[2].Evidence = []string{"authToken present in config.xml"}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "    · authToken present in config.xml") {
		t.Errorf("evidence should be an indented bullet:\n%s", buf.String())
	}
}

func TestManualAggregatesPerControlWithCount(t *testing.T) {
	rep := sample()
	// Automated=false makes these true MANUAL controls; an automated control
	// reporting MANUAL is unread and folds into the one-sentence summary.
	for i := range rep.Findings {
		if rep.Findings[i].Status == engine.StatusManual {
			rep.Findings[i].Automated = false
		}
	}
	extra := finding("CIS-2.3.5", "another-job", engine.ResourceJob, engine.StatusManual, "MEDIUM")
	extra.Automated = false
	rep.Findings = append(rep.Findings, extra)
	rep.Score = engine.Compute(rep.Findings)
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "CIS-2.3.5 MANUAL (2 jobs): ") {
		t.Errorf("two same-reason MANUAL findings should fold to one counted line:\n%s", out)
	}
	if strings.Count(out, "CIS-2.3.5 MANUAL") != 1 {
		t.Errorf("the group should render exactly once:\n%s", out)
	}
}

// Two different reasons must not collapse under whichever came first.
func TestManualGroupSplitsOnDifferentDetails(t *testing.T) {
	rep := sample()
	for i := range rep.Findings {
		if rep.Findings[i].Status == engine.StatusManual {
			rep.Findings[i].Automated = false
		}
	}
	other := finding("CIS-2.3.5", "another-job", engine.ResourceJob, engine.StatusManual, "MEDIUM")
	other.Automated = false
	other.Details = "a different reason entirely"
	rep.Findings = append(rep.Findings, other)
	rep.Score = engine.Compute(rep.Findings)
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "CIS-2.3.5 MANUAL") != 2 {
		t.Errorf("different reasons should keep their own lines:\n%s", buf.String())
	}
}

// The verdict is the last thing printed; every number above it is checkable on
// the way down.
func TestScoreTrailerEndsTheReport(t *testing.T) {
	out := render(t, FormatTable, Options{})
	scoreAt := strings.LastIndex(out, "SCORE ")
	if scoreAt < 0 {
		t.Fatalf("no score block:\n%s", out)
	}
	for _, section := range []string{"CIS-2.3.1", "fix: ", "Rules"} {
		if at := strings.Index(out, section); at > scoreAt {
			t.Errorf("%q appears after the score trailer", section)
		}
	}
	// Nothing but the score block's own lines after it.
	tail := out[scoreAt:]
	if strings.Contains(tail, "fix: ") || strings.Contains(tail, "MANUAL (") {
		t.Errorf("the trailer should close the report:\n%s", tail)
	}
}

func TestRulesIndexListsEachFailedControlOnce(t *testing.T) {
	out := render(t, FormatTable, Options{})
	at := strings.Index(out, "Rules")
	if at < 0 {
		t.Fatalf("no rules index:\n%s", out)
	}
	tail := out[at:]
	// Two failing controls, one line each — the fixture gives both the same
	// URL, so count IDs rather than links.
	for _, id := range []string{"CIS-2.1.6", "CIS-2.3.1"} {
		if strings.Count(tail, id) != 1 {
			t.Errorf("%s should appear exactly once in the rules index:\n%s", id, tail)
		}
	}
}

// Every line fits the terminal, except lines carrying a single unbreakable
// token (a URL, a long resource name) that no wrap could improve.
func TestEveryLineFitsTheTerminalWidth(t *testing.T) {
	const width = 80
	rep := sample()
	rep.Findings[2].Evidence = []string{"an authentication token is set under Build Triggers"}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: width}); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if len(l) <= width {
			continue
		}
		// An unbreakable token exemption: the overflowing part must contain no
		// spaces after the wrap point, i.e. the line has at most one long word.
		fields := strings.Fields(l)
		longest := 0
		for _, f := range fields {
			if len(f) > longest {
				longest = len(f)
			}
		}
		if longest <= width/2 {
			t.Errorf("line overflows %d columns without an unbreakable token: %q", width, l)
		}
	}
}

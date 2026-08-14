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
	if !strings.Contains(out, engine.InstanceResourceName) {
		t.Errorf("a controller-scope finding should name the controller:\n%s", out)
	}
	// The legend explains the invented word, so the two must agree.
	if strings.Contains(out, "Legend") && !strings.Contains(out, "'"+engine.InstanceResourceName+"'") {
		t.Errorf("the legend does not explain %q:\n%s", engine.InstanceResourceName, out)
	}
}

func TestTableCarriesRemediation(t *testing.T) {
	out := render(t, FormatTable, Options{})
	if !strings.Contains(out, "Manage Jenkins") {
		t.Errorf("a failing control's fix should name a place to act:\n%s", out)
	}
}

func TestNoRemediationsDropsTheSection(t *testing.T) {
	with := render(t, FormatTable, Options{})
	without := render(t, FormatTable, Options{NoRemediations: true})
	if len(without) >= len(with) {
		t.Error("--no-remediations should shorten the report")
	}
	if strings.Contains(without, "Remediations") {
		t.Error("the remediation section should be gone")
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
	// resource that has a finding has to appear by name.
	for _, resource := range []string{"legacy-build", "platform/api-service"} {
		if !strings.Contains(details, resource) {
			t.Errorf("the details layout does not name %q:\n%s", resource, details)
		}
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
	for _, want := range []string{"no-such-job", "Report Summary", "list-checks"} {
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

package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
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
	rep.Coverage = engine.Coverage{Jobs: 3, JobControls: 5, Complete: true}
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

// A run that judged no job must not look like one whose jobs were all fine, in
// any format: the table says so beside the score, and SARIF marks the run as
// not having executed successfully, which code scanning surfaces instead of
// closing every job alert as fixed.
func TestNoJobsAuditedIsVisibleInEveryFormat(t *testing.T) {
	rep := sample()
	rep.Coverage = engine.Coverage{Jobs: 0, JobControls: 5, Complete: true}

	var table bytes.Buffer
	if err := Write(&table, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "no job was evaluated") {
		t.Errorf("the table should say no job was evaluated:\n%s", table.String())
	}

	var sarif bytes.Buffer
	if err := Write(&sarif, rep, Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("a run that judged no job did not execute successfully")
	}

	var js bytes.Buffer
	if err := Write(&js, rep, Options{Format: FormatJSON}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"jobControls": 5`) {
		t.Errorf("the JSON report should carry the coverage:\n%s", js.String())
	}
}

// A folder that could not be listed is as invisible in a report as a job with
// nothing wrong — unless the report says so, in every format.
func TestIncompleteListingIsVisibleInEveryFormat(t *testing.T) {
	rep := sample()
	rep.Coverage = engine.Coverage{Jobs: 3, JobControls: 5, Complete: false, Unlisted: []string{"prod"}}

	var table bytes.Buffer
	if err := Write(&table, rep, Options{Format: FormatTable, Width: 100}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "the job list is incomplete: 1 container could not be listed") {
		t.Errorf("the table should say the job list is incomplete:\n%s", table.String())
	}

	var sarif bytes.Buffer
	if err := Write(&sarif, rep, Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"executionSuccessful": false`) {
		t.Errorf("an incomplete scan did not execute successfully:\n%s", sarif.String())
	}
	if !strings.Contains(sarif.String(), "could not be listed") {
		t.Error("SARIF should carry a notification saying why")
	}

	complete := sample()
	sarif.Reset()
	if err := Write(&sarif, complete, Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"executionSuccessful": true`) {
		t.Error("a complete scan with no policy errors executed successfully")
	}
}

// sarifDoc is the part of a SARIF log the code-scanning tests read.
type sarifDoc struct {
	Runs []struct {
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Tool struct {
			Driver struct {
				Rules []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties map[string]any `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			Level     string                `json:"level"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region map[string]int `json:"region"`
				} `json:"physicalLocation"`
				LogicalLocations []struct {
					Name string `json:"name"`
					Kind string `json:"kind"`
				} `json:"logicalLocations"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Message struct{ Text string } `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

func sarifOf(t *testing.T, rep *engine.Report) sarifDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// GitHub code scanning drops a result without a physicalLocation: the upload
// succeeds and the Security tab stays empty (scm-bench/jenkins-bench#10).
// Every result carries one now, a relative path naming the platform, the
// controller and the resource, with the region GitHub requires.
func TestSARIFResultsCarryAPhysicalLocation(t *testing.T) {
	rep := sample()
	rep.Findings = append(rep.Findings,
		finding("CIS-2.3.5", "Équipe A+B/déploiement (prod)", engine.ResourceJob, engine.StatusFail, "MEDIUM"),
		finding("CIS-2.3.5", "platform/mb/release%2F1.0", engine.ResourceJob, engine.StatusFail, "MEDIUM"))
	doc := sarifOf(t, rep)
	run := doc.Runs[0]
	if run.AutomationDetails.ID != "jenkins-bench/jenkins.invalid/" {
		t.Errorf("automationDetails.id = %q; two controllers uploading to one repository must not share it", run.AutomationDetails.ID)
	}
	uris := map[string]bool{}
	for _, r := range run.Results {
		if len(r.Locations) != 1 {
			t.Fatalf("%s: %d locations", r.RuleID, len(r.Locations))
		}
		loc := r.Locations[0]
		uri := loc.PhysicalLocation.ArtifactLocation.URI
		uris[uri] = true
		if !strings.HasPrefix(uri, "jenkins/jenkins.invalid/") {
			t.Errorf("%s: uri %q should start with the platform and controller", r.RuleID, uri)
		}
		if loc.PhysicalLocation.Region["startLine"] != 1 || loc.PhysicalLocation.Region["endColumn"] != 1 {
			t.Errorf("%s: region = %v", r.RuleID, loc.PhysicalLocation.Region)
		}
		if len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].Name == "" {
			t.Errorf("%s: logical location missing", r.RuleID)
		}
		hash := r.PartialFingerprints["primaryLocationLineHash"]
		if !strings.HasSuffix(hash, ":1") || len(hash) != 34 {
			t.Errorf("%s: primaryLocationLineHash = %q", r.RuleID, hash)
		}
		if r.PartialFingerprints["scmBenchFindingV1"] == "" {
			t.Errorf("%s: the family fingerprint is gone", r.RuleID)
		}
	}
	for _, want := range []string{
		"jenkins/jenkins.invalid/controller",
		"jenkins/jenkins.invalid/legacy-build",
		"jenkins/jenkins.invalid/%C3%89quipe%20A+B/d%C3%A9ploiement%20%28prod%29",
		"jenkins/jenkins.invalid/platform/mb/release%252F1.0",
	} {
		if !uris[want] {
			t.Errorf("no result located at %s; got %v", want, uris)
		}
	}
}

// GitHub shows an alert at its rule's security-severity. A MANUAL result
// shared its control's rule, so "a person needs to check this" displayed as
// High once any job failed the same control.
func TestSARIFKeepsManualResultsOffTheSeverityScale(t *testing.T) {
	doc := sarifOf(t, sample())
	rules := map[string]map[string]any{}
	levels := map[string]string{}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		rules[r.ID] = r.Properties
		levels[r.ID] = r.DefaultConfiguration.Level
	}
	if rules["CIS-2.1.6"]["security-severity"] != "8.0" || levels["CIS-2.1.6"] != "error" {
		t.Errorf("a HIGH failure's rule = %v / %s", rules["CIS-2.1.6"], levels["CIS-2.1.6"])
	}
	manual, ok := rules["CIS-2.3.5/manual"]
	if !ok {
		t.Fatalf("MANUAL results need a rule of their own: %v", rules)
	}
	if _, has := manual["security-severity"]; has || levels["CIS-2.3.5/manual"] != "note" {
		t.Errorf("a manual rule must carry no security-severity and be a note: %v / %s", manual, levels["CIS-2.3.5/manual"])
	}
	for _, r := range doc.Runs[0].Results {
		if strings.HasSuffix(r.RuleID, "/manual") && r.Level != "note" {
			t.Errorf("%s: a manual result is a note, got %s", r.RuleID, r.Level)
		}
		if r.RuleID == "CIS-2.3.1" && strings.Contains(r.Message.Text, "platform/api-service") {
			t.Error("a PASS was emitted")
		}
	}
	if securitySeverity("LOW") != "2.0" {
		t.Errorf("LOW maps to %s, want 2.0 like the other benches", securitySeverity("LOW"))
	}
}

// A control no API can answer is one question for a person: one result for
// the control, at the controller, not one per job.
func TestSARIFReportsAManualByDesignControlOnce(t *testing.T) {
	rep := &engine.Report{Metadata: sample().Metadata, Coverage: engine.Coverage{Complete: true}}
	for _, job := range []string{"a", "b", "c"} {
		f := finding("CIS-2.1.1", job, engine.ResourceJob, engine.StatusManual, "MEDIUM")
		f.Automated = false
		rep.Findings = append(rep.Findings, f)
	}
	rep.Score = engine.Compute(rep.Findings)
	results := sarifOf(t, rep).Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("%d results, want one for the control", len(results))
	}
	r := results[0]
	if r.RuleID != "CIS-2.1.1/manual" || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "jenkins/jenkins.invalid/controller" {
		t.Errorf("result = %+v", r)
	}
	if !strings.Contains(r.Message.Text, "3 jobs") {
		t.Errorf("the message should say how many jobs it covers: %s", r.Message.Text)
	}
}

// GitHub keeps the 5,000 most severe results of a run and rejects one past
// 25,000; a 10,000-job controller produces some 30,000. The run keeps the most
// severe itself, and says how many it withheld.
func TestSARIFCapsResultsMostSevereFirst(t *testing.T) {
	rep := &engine.Report{Metadata: sample().Metadata, Coverage: engine.Coverage{Complete: true}}
	for i := 0; i < maxSARIFResults+10; i++ {
		rep.Findings = append(rep.Findings, finding("CIS-2.3.5", fmt.Sprintf("job-%05d", i), engine.ResourceJob, engine.StatusManual, "MEDIUM"))
	}
	rep.Findings = append(rep.Findings, finding("CIS-2.3.1", "legacy", engine.ResourceJob, engine.StatusFail, "HIGH"))
	rep.Score = engine.Compute(rep.Findings)
	doc := sarifOf(t, rep)
	results := doc.Runs[0].Results
	if len(results) != maxSARIFResults {
		t.Fatalf("%d results, want the cap of %d", len(results), maxSARIFResults)
	}
	if results[0].RuleID != "CIS-2.3.1" {
		t.Errorf("the failure should survive the cap first, got %s", results[0].RuleID)
	}
	found := false
	for _, n := range doc.Runs[0].Invocations[0].ToolExecutionNotifications {
		if strings.Contains(n.Message.Text, "11 less severe results were withheld") && strings.Contains(n.Message.Text, "-o json") {
			found = true
		}
	}
	if !found {
		t.Error("the run should say how many results it withheld, and where to find them")
	}
}

// An accepted finding carries SARIF's own suppression, which code scanning
// shows as dismissed with the justification, rather than as an open alert.
func TestSARIFCarriesAcceptedFindingsAsSuppressed(t *testing.T) {
	rep := sample()
	for i := range rep.Findings {
		if rep.Findings[i].CheckID == "CIS-2.3.1" && rep.Findings[i].Status == engine.StatusFail {
			rep.Findings[i].Waiver = &engine.Waiver{Reason: "vendor job", Owner: "platform", Expires: "2027-03-31"}
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, r := range log.Runs[0].Results {
		if r.RuleID != "CIS-2.3.1" {
			if len(r.Suppressions) != 0 {
				t.Errorf("%s was not accepted but carries a suppression", r.RuleID)
			}
			continue
		}
		seen = true
		s := r.Suppressions
		if len(s) != 1 || s[0].Kind != "external" || s[0].Status != "accepted" || !strings.Contains(s[0].Justification, "vendor job") {
			t.Errorf("suppressions = %+v", s)
		}
	}
	if !seen {
		t.Fatal("no CIS-2.3.1 result")
	}
}

// The table lists an accepted finding under its own heading, never among the
// failures, and says beside the score why a FAIL count did not fail the run.
func TestTableSetsAcceptedFindingsApart(t *testing.T) {
	rep := sample()
	for i := range rep.Findings {
		if rep.Findings[i].CheckID == "CIS-2.3.1" && rep.Findings[i].Status == engine.StatusFail {
			rep.Findings[i].Waiver = &engine.Waiver{Reason: "vendor job", Expires: "2027-03-31"}
		}
	}
	rep.ExceptionWarnings = []string{"the exception for CIS-2.1.6 on controller lapsed on 2026-01-01"}
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatTable, Width: 120}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Accepted by exceptions (1)",
		"legacy-build  CIS-2.3.1 FAIL: accepted until 2027-03-31: vendor job",
		"1 failed finding accepted by exceptions",
		"Exceptions",
		"lapsed on 2026-01-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "legacy-build  CIS-2.3.1 HIGH") {
		t.Errorf("an accepted finding was listed among the failures:\n%s", out)
	}

	var details bytes.Buffer
	if err := Write(&details, rep, Options{Format: FormatTable, Width: 160, Details: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details.String(), "accepted until 2027-03-31") {
		t.Errorf("the details view should carry the note in the finding cell:\n%s", details.String())
	}
}

type junitDoc struct {
	Tests      int `xml:"tests,attr"`
	Failures   int `xml:"failures,attr"`
	Skipped    int `xml:"skipped,attr"`
	Properties struct {
		Property []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"property"`
	} `xml:"properties"`
	Suites []struct {
		Name  string `xml:"name,attr"`
		Cases []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Type string `xml:"type,attr"`
				Text string `xml:",chardata"`
			} `xml:"failure"`
			Skipped *struct {
				Message string `xml:"message,attr"`
			} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func junitOf(t *testing.T, rep *engine.Report) (junitDoc, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, rep, Options{Format: FormatJUnit, ToolVersion: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	var doc junitDoc
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JUnit output does not parse: %v\n%s", err, buf.String())
	}
	return doc, buf.String()
}

// JUnit is for the CI systems that draw test results natively. Every finding
// is a test case, so the totals add up and nothing is silently dropped; only
// an unaccepted FAIL is a failure.
func TestJUnitCountsEveryFindingAndFailsOnlyRealFailures(t *testing.T) {
	rep := sample()
	accepted := finding("CIS-2.3.1", "vendor/job", engine.ResourceJob, engine.StatusFail, "HIGH")
	accepted.Waiver = &engine.Waiver{Reason: "migration", Expires: "2027-01-01"}
	rep.Findings = append(rep.Findings, accepted)
	doc, raw := junitOf(t, rep)

	// sample(): FAIL controller, PASS api-service, FAIL legacy-build, MANUAL
	// legacy-build, NA disabled-job — plus the accepted failure.
	if doc.Tests != 6 || doc.Failures != 2 || doc.Skipped != 3 {
		t.Errorf("totals tests=%d failures=%d skipped=%d, want 6/2/3\n%s", doc.Tests, doc.Failures, doc.Skipped, raw)
	}
	cases := map[string]string{}
	for _, s := range doc.Suites {
		if !strings.Contains(s.Name, ": ") {
			t.Errorf("suite name %q should be \"ID: title\"", s.Name)
		}
		for _, c := range s.Cases {
			key := c.ClassName + " " + c.Name
			switch {
			case c.Failure != nil:
				cases[key] = "failure:" + c.Failure.Type
				if !strings.Contains(c.Failure.Text, "Fix: ") {
					t.Errorf("failure text %q carries no fix", c.Failure.Text)
				}
			case c.Skipped != nil:
				cases[key] = "skipped:" + c.Skipped.Message
			default:
				cases[key] = "pass"
			}
		}
	}
	for key, want := range map[string]string{
		"CIS-2.1.6 controller":           "failure:HIGH",
		"CIS-2.3.1 legacy-build":         "failure:HIGH",
		"CIS-2.3.1 platform/api-service": "pass",
		"CIS-2.3.5 legacy-build":         "skipped:MANUAL: one sentence about this resource",
		"CIS-2.2.3 disabled-job":         "skipped:not applicable: one sentence about this resource",
		"CIS-2.3.1 vendor/job":           "skipped:FAIL, accepted until 2027-01-01: migration",
	} {
		if cases[key] != want {
			t.Errorf("%s = %q, want %q", key, cases[key], want)
		}
	}
	props := map[string]string{}
	for _, p := range doc.Properties.Property {
		props[p.Name] = p.Value
	}
	if props["toolVersion"] != "1.2.3" || props["platform"] != "jenkins" || props["baseUrl"] == "" || props["score"] == "" {
		t.Errorf("properties = %v", props)
	}
}

// Jobs a scan never saw have no test case to fail, so a scan that could not
// list a folder, judged no job, or lost a policy carries failing cases of its
// own rather than rendering as a clean run.
func TestJUnitFailsAScanThatCouldNotDoItsJob(t *testing.T) {
	rep := sample()
	rep.Coverage = engine.Coverage{Jobs: 0, JobControls: 5, Complete: false, Unlisted: []string{"locked"}}
	rep.Errors = []string{"CIS-2.3.1 on x: policy evaluation failed"}
	_, raw := junitOf(t, rep)
	for _, want := range []string{`name="scan"`, `name="locked" classname="scan.coverage"`, `name="jobs" classname="scan.coverage"`, `classname="scan.policy"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("JUnit is missing %s:\n%s", want, raw)
		}
	}

	unrecorded := sample()
	unrecorded.Coverage = engine.Coverage{Jobs: 3, JobControls: 5}
	if _, raw := junitOf(t, unrecorded); !strings.Contains(raw, `name="job list" classname="scan.coverage"`) {
		t.Errorf("a snapshot with no completeness record should fail in JUnit:\n%s", raw)
	}
}

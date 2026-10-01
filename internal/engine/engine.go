// Package engine compiles the embedded Rego policies once and evaluates them
// against a snapshot. It owns no policy logic of its own: every verdict comes
// from a rule, and the engine only decides which resources a rule sees.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/config"
)

// Status is the outcome of one control against one resource.
type Status string

const (
	// StatusPass means the control is satisfied.
	StatusPass Status = "PASS"
	// StatusFail means the control is not satisfied.
	StatusFail Status = "FAIL"
	// StatusManual means the instance did not expose enough data to decide.
	// It never counts towards the score, because guessing would be worse than
	// admitting the gap.
	StatusManual Status = "MANUAL"
	// StatusNA means the control does not apply to this resource.
	StatusNA Status = "NA"
)

// Resource kinds a finding can be attached to.
const (
	ResourceJob        = "job"
	ResourceController = "controller"
)

// InstanceResourceName labels findings that apply to the controller as a whole.
const InstanceResourceName = "controller"

// Finding is one control evaluated against one resource.
type Finding struct {
	CheckID      string `json:"checkId"`
	CISID        string `json:"cisId"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Status       Status `json:"status"`
	Resource     string `json:"resource"`
	ResourceType string `json:"resourceType"`
	// Description is why the control exists, carried from its metadata. It
	// explains the finding to someone who is not already convinced the control
	// matters — Details says what this resource does, Remediation says what to
	// change, and neither answers "why should I care".
	Description string   `json:"description,omitempty"`
	Details     string   `json:"details"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	// FixSummary is Remediation's first move in one line. The table report
	// prints it beside the verdict and keeps the full paragraph for its own
	// section; consumers that want everything should read Remediation.
	FixSummary string   `json:"fixSummary,omitempty"`
	References []string `json:"references,omitempty"`
	// Automated is false for controls that are documented as unanswerable by
	// the API and always report MANUAL.
	Automated bool `json:"automated"`
	// Waiver is set when a configured exception accepts this finding. The
	// status is unchanged — an accepted FAIL is still a FAIL, and still counts
	// in the score — but it no longer fails the run.
	Waiver *Waiver `json:"waiver,omitempty"`
}

// Waiver is the exception that accepted a finding, as the report shows it.
type Waiver struct {
	Reason  string `json:"reason"`
	Owner   string `json:"owner,omitempty"`
	Expires string `json:"expires"`
}

// Report is the full result of an evaluation.
type Report struct {
	Metadata ci.Metadata `json:"metadata"`
	Findings []Finding   `json:"findings"`
	Score    Score       `json:"score"`
	// Coverage is how much of the controller the findings describe. The score
	// cannot say it: a scan that judged no job scores exactly like one whose
	// jobs were all fine.
	Coverage Coverage `json:"coverage"`
	// Errors records policies that failed to evaluate. They surface as MANUAL
	// findings too, so a broken rule is loud but not fatal.
	Errors []string `json:"errors,omitempty"`
	// ExceptionWarnings names configured exceptions that did nothing this
	// run: lapsed ones, and ones no finding matched any more. Both are how an
	// exceptions list rots, so both are said out loud.
	ExceptionWarnings []string `json:"exceptionWarnings,omitempty"`
}

// Coverage counts what the job-scope controls were evaluated against.
type Coverage struct {
	// Jobs is how many jobs the job-scope controls were evaluated against.
	Jobs int `json:"jobs"`
	// SkippedDisabled is how many jobs scan.skipDisabledJobs left out.
	SkippedDisabled int `json:"skippedDisabled,omitempty"`
	// JobControls is how many job-scope controls the run selected. Zero jobs
	// only means "nothing was audited" when at least one control asked about
	// jobs; a run narrowed to controller-scope controls asked nothing.
	JobControls int `json:"jobControls"`
	// Complete is false when part of the job tree could not be listed. The
	// jobs in it are missing from the findings rather than judged, and
	// nothing else in a report would show it: an absent job reads exactly
	// like a job with nothing wrong.
	Complete bool `json:"complete"`
	// Unlisted names the containers whose job list could not be read, "/"
	// for the top level.
	Unlisted []string `json:"unlisted,omitempty"`
}

// NoJobsAudited reports whether the run asked about jobs and had none to ask
// about. A token without Job/Read is shown an empty job list rather than a
// 403, so this is the only place that case becomes visible.
func (c Coverage) NoJobsAudited() bool {
	return c.JobControls > 0 && c.Jobs == 0
}

// Engine holds the compiled policy bundle.
type Engine struct {
	cfg      config.Config
	bundle   *checks.Bundle
	prepared map[string]rego.PreparedEvalQuery
	selected []checks.Check
	// now decides which exceptions have lapsed; a field so tests can fix it.
	now func() time.Time
}

// New compiles the embedded policies for the given platform and configuration.
func New(ctx context.Context, cfg config.Config, platform string) (*Engine, error) {
	bundle, err := checks.Load()
	if err != nil {
		return nil, fmt.Errorf("load policy bundle: %w", err)
	}

	// A check ID that names nothing is almost always a typo, and the silent
	// reading of it is the dangerous one: an `exclude` that matches no control
	// leaves that control running, and an `include` that matches none would
	// narrow the scan to nothing. Both look like a successful scan.
	if err := validateSelection(cfg, bundle); err != nil {
		return nil, err
	}

	modules := make(map[string]string, len(bundle.Modules))
	for _, m := range bundle.Modules {
		modules[m.Path] = m.Source
	}
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}

	e := &Engine{
		cfg:      cfg,
		bundle:   bundle,
		prepared: make(map[string]rego.PreparedEvalQuery),
	}

	for _, check := range bundle.Checks {
		if !check.AppliesTo(platform) || !cfg.Selects(check.ID) {
			continue
		}
		query := fmt.Sprintf("data.%s.result", check.Package)
		pq, prepErr := rego.New(
			rego.Query(query),
			rego.Compiler(compiler),
		).PrepareForEval(ctx)
		if prepErr != nil {
			return nil, fmt.Errorf("prepare %s (%s): %w", check.ID, query, prepErr)
		}
		e.prepared[check.ID] = pq
		e.selected = append(e.selected, check)
	}

	if len(e.selected) == 0 {
		return nil, fmt.Errorf("no checks selected for platform %q", platform)
	}
	return e, nil
}

// Checks returns the controls this engine will evaluate, in benchmark order.
func (e *Engine) Checks() []checks.Check { return e.selected }

// validateSelection rejects include/exclude entries that name no control in the
// bundle. IDs are compared case-insensitively and trimmed, matching how
// config.Selects reads them, so the two cannot disagree about what is known.
func validateSelection(cfg config.Config, bundle *checks.Bundle) error {
	known := make(map[string]bool, len(bundle.Checks))
	for _, c := range bundle.Checks {
		known[strings.ToUpper(c.ID)] = true
	}

	var unknown []string
	for _, list := range [][]string{cfg.Include, cfg.Exclude} {
		for _, id := range list {
			id = strings.TrimSpace(id)
			if id == "" || known[strings.ToUpper(id)] {
				continue
			}
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown check ID(s) in include/exclude: %s; run `jenkins-bench list-checks` for the %d valid IDs",
		strings.Join(unknown, ", "), len(bundle.Checks))
}

// Evaluate runs every selected control against every resource in the snapshot.
//
// Each resource's input holds only what its scope reads. v0.1 handed every job
// evaluation the whole controller — agents, credentials, plugins — as
// input.controller, which no job policy reads, and converted it again for every
// job and every control: 10,000 jobs on a controller with 1,000 agents took 861
// seconds, almost all of it spent building inputs nobody looked at. A job's
// input is now the job and the thresholds; each resource is converted to OPA's
// value form once and handed to every control as a parsed input; and jobs are
// evaluated in parallel, which the prepared queries allow.
func (e *Engine) Evaluate(ctx context.Context, snapshot *ci.Snapshot) (*Report, error) {
	cfgValue, err := toAST(e.cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	metaValue, err := toAST(snapshot.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot metadata: %w", err)
	}
	controllerValue, err := toAST(snapshot.Controller)
	if err != nil {
		return nil, fmt.Errorf("encode controller: %w", err)
	}

	report := &Report{Metadata: snapshot.Metadata}

	var jobs []ci.Job
	for _, job := range snapshot.Jobs {
		// Applied here as well as in the fetcher, so the setting means the same
		// thing whichever way a job arrived: the same file and the same config
		// must not produce two answers depending on whether the snapshot came
		// off the wire or off disk.
		if e.cfg.SkipDisabledJobs && job.Disabled {
			report.Coverage.SkippedDisabled++
			continue
		}
		jobs = append(jobs, job)
	}
	report.Coverage.Jobs = len(jobs)
	// A snapshot that does not record the listing as complete is treated as
	// incomplete: a key nobody set proves nothing about the jobs it would
	// have covered.
	report.Coverage.Complete = snapshot.Controller.Available["jobs"]
	report.Coverage.Unlisted = append([]string(nil), snapshot.Controller.Unlisted...)

	var controllerChecks, jobChecks []checks.Check
	for _, check := range e.selected {
		switch check.Scope {
		case checks.ScopeController:
			controllerChecks = append(controllerChecks, check)
		case checks.ScopeJob:
			jobChecks = append(jobChecks, check)
		}
	}
	report.Coverage.JobControls = len(jobChecks)

	// The controller-scope controls are the only ones that read the capture
	// time (plugin currency compares it with the update centre's).
	controllerInput := inputObject(controllerValue, cfgValue, metaValue)
	for _, check := range controllerChecks {
		finding, errMsg := e.evaluateOne(ctx, check, InstanceResourceName, ResourceController, controllerInput)
		report.Findings = append(report.Findings, finding)
		if errMsg != "" {
			report.Errors = append(report.Errors, errMsg)
		}
	}

	results, err := e.evaluateJobs(ctx, jobs, jobChecks, cfgValue)
	if err != nil {
		return nil, err
	}
	// Merged in job order, so the policy errors read the same on every run;
	// the findings are sorted below whatever order they arrive in.
	for _, r := range results {
		report.Findings = append(report.Findings, r.findings...)
		report.Errors = append(report.Errors, r.errors...)
	}

	sortFindings(report.Findings)
	report.Score = Compute(report.Findings)
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	report.ExceptionWarnings = applyExceptions(report.Findings, e.cfg.Exceptions, now())
	return report, nil
}

// applyExceptions marks the findings configured exceptions accept and returns
// what is worth telling the operator about the exceptions themselves.
//
// Only FAIL and MANUAL findings can be accepted: there is nothing to accept
// about a PASS or an NA. The score is computed before this runs and does not
// change — it describes the controller, and accepting a finding does not
// change the controller.
func applyExceptions(findings []Finding, exceptions []config.Exception, now time.Time) []string {
	var warnings []string
	for _, ex := range exceptions {
		if !now.Before(ex.ExpiresAt()) {
			warnings = append(warnings, fmt.Sprintf("the exception for %s on %s lapsed on %s; its findings fail the run again (%s)",
				ex.Control, strings.Join(ex.Resources, ", "), ex.Expires, ex.Reason))
			continue
		}
		matched := 0
		for i := range findings {
			f := &findings[i]
			if !strings.EqualFold(f.CheckID, ex.Control) || !resourceMatches(ex.Resources, f.Resource) {
				continue
			}
			if f.Status != StatusFail && f.Status != StatusManual {
				continue
			}
			if f.Waiver == nil {
				f.Waiver = &Waiver{Reason: ex.Reason, Owner: ex.Owner, Expires: ex.Expires}
			}
			matched++
		}
		if matched == 0 {
			warnings = append(warnings, fmt.Sprintf("the exception for %s on %s accepts nothing this run — the finding is fixed, renamed or out of scope; remove it",
				ex.Control, strings.Join(ex.Resources, ", ")))
		}
	}
	return warnings
}

// resourceMatches compares case-sensitively, as Jenkins names its items:
// platform/legacy-* must not accept a job in a different folder called
// Platform.
func resourceMatches(patterns []string, resource string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, resource); ok {
			return true
		}
	}
	return false
}

// jobResult is one job's findings, and the policy errors behind any of them.
type jobResult struct {
	findings []Finding
	errors   []string
}

// evaluateJobs runs the job-scope controls against every job, a worker per
// CPU. Each job is converted to OPA's value form once, by the worker that
// evaluates it, and the result lands at the job's own index.
func (e *Engine) evaluateJobs(ctx context.Context, jobs []ci.Job, jobChecks []checks.Check, cfgValue ast.Value) ([]jobResult, error) {
	results := make([]jobResult, len(jobs))
	if len(jobChecks) == 0 || len(jobs) == 0 {
		return results, nil
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > len(jobs) {
		workers = len(jobs)
	}

	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				value, err := toAST(jobs[i])
				if err != nil {
					errOnce.Do(func() { firstErr = fmt.Errorf("encode job %s: %w", jobs[i].FullName, err) })
					continue
				}
				input := inputObject(value, cfgValue, nil)
				r := &results[i]
				for _, check := range jobChecks {
					finding, errMsg := e.evaluateOne(ctx, check, jobs[i].FullName, ResourceJob, input)
					r.findings = append(r.findings, finding)
					if errMsg != "" {
						r.errors = append(r.errors, errMsg)
					}
				}
			}
		}()
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()
	return results, firstErr
}

// inputObject assembles one evaluation's input from values already converted:
// the resource, the thresholds, and — for the controller only — the snapshot
// metadata.
func inputObject(resource, config, metadata ast.Value) ast.Value {
	items := [][2]*ast.Term{
		ast.Item(ast.StringTerm("resource"), ast.NewTerm(resource)),
		ast.Item(ast.StringTerm("config"), ast.NewTerm(config)),
	}
	if metadata != nil {
		items = append(items, ast.Item(ast.StringTerm("metadata"), ast.NewTerm(metadata)))
	}
	return ast.NewObject(items...)
}

// evaluateOne runs a single control against a single resource. A policy that
// errors or returns nothing yields a MANUAL finding carrying the reason, so a
// broken rule is visible in the report instead of silently missing; the
// reason comes back as errMsg for the report's errors.
func (e *Engine) evaluateOne(ctx context.Context, check checks.Check, resource, resourceType string, input ast.Value) (Finding, string) {
	finding := Finding{
		CheckID:      check.ID,
		CISID:        check.CISID,
		Title:        check.Title,
		Severity:     strings.ToUpper(check.Severity),
		Resource:     resource,
		ResourceType: resourceType,
		Description:  check.Description,
		Remediation:  check.Remediation,
		FixSummary:   check.FixSummary,
		References:   check.References,
		Automated:    check.Automated,
	}

	rs, err := e.prepared[check.ID].Eval(ctx, rego.EvalParsedInput(input))
	if err != nil {
		finding.Status = StatusManual
		finding.Details = "This control could not be evaluated because its policy failed to run: " + err.Error()
		return finding, fmt.Sprintf("%s on %s: policy evaluation failed: %v", check.ID, resource, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		finding.Status = StatusManual
		finding.Details = "This control could not be evaluated because its policy produced no result."
		return finding, fmt.Sprintf("%s on %s: policy produced no result", check.ID, resource)
	}

	decoded, err := decodeResult(rs[0].Expressions[0].Value)
	if err != nil {
		finding.Status = StatusManual
		finding.Details = "This control returned a malformed result: " + err.Error()
		return finding, fmt.Sprintf("%s on %s: %v", check.ID, resource, err)
	}

	finding.Status = decoded.Status
	finding.Details = decoded.Details
	finding.Evidence = decoded.Evidence
	return finding, ""
}

type policyResult struct {
	Status   Status
	Details  string
	Evidence []string
}

func decodeResult(value any) (policyResult, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return policyResult{}, fmt.Errorf("policy result is %T, want an object", value)
	}

	statusRaw, _ := obj["status"].(string)
	status := Status(strings.ToUpper(strings.TrimSpace(statusRaw)))
	switch status {
	case StatusPass, StatusFail, StatusManual, StatusNA:
	default:
		return policyResult{}, fmt.Errorf("policy result status %q is not PASS, FAIL, MANUAL or NA", statusRaw)
	}

	details, _ := obj["details"].(string)
	if strings.TrimSpace(details) == "" {
		return policyResult{}, fmt.Errorf("policy result is missing details")
	}

	var evidence []string
	if raw, present := obj["evidence"]; present {
		items, isSlice := raw.([]any)
		if !isSlice {
			return policyResult{}, fmt.Errorf("policy result evidence is %T, want an array", raw)
		}
		for _, item := range items {
			evidence = append(evidence, fmt.Sprintf("%v", item))
		}
	}

	return policyResult{Status: status, Details: details, Evidence: evidence}, nil
}

// toAST converts a Go value into OPA's value form, honouring the json tags
// that define the snapshot's contract with the rules. Done once per resource:
// a value handed to Eval as plain maps is converted again on every call.
func toAST(v any) (ast.Value, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var plain any
	if err := json.Unmarshal(raw, &plain); err != nil {
		return nil, err
	}
	return ast.InterfaceToValue(plain)
}

// sortFindings orders the report the way it is read: worst first, then by
// benchmark number, then by resource.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
			return ra < rb
		}
		if wa, wb := checks.Weight(a.Severity), checks.Weight(b.Severity); wa != wb {
			return wa > wb
		}
		if a.CISID != b.CISID {
			return checks.LessCISID(a.CISID, b.CISID)
		}
		return a.Resource < b.Resource
	})
}

func statusRank(s Status) int {
	switch s {
	case StatusFail:
		return 0
	case StatusManual:
		return 1
	case StatusPass:
		return 2
	default:
		return 3
	}
}

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/ci/jenkins"
	"github.com/scm-bench/jenkins-bench/internal/config"
	"github.com/scm-bench/jenkins-bench/internal/console"
	"github.com/scm-bench/jenkins-bench/internal/engine"
	"github.com/scm-bench/jenkins-bench/internal/report"
)

type scanOptions struct {
	baseURL  string
	username string
	token    string

	configPath  string
	sets        []string
	snapshotIn  string
	snapshotOut string

	format         string
	details        string
	detailsSet     bool
	showPassed     bool
	noRemediations bool
	noColor        bool

	scan config.Scan
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Jenkins controller",
		Long: `Scan captures a read-only snapshot of a Jenkins controller and evaluates it
against the benchmark.

Every request is a GET, and the snapshot holds no secrets: a job's remote
trigger token is recorded as present or absent, never as a value, so the file
is safe to attach to a bug report.

What the token can read decides what the report can say. A least-privilege
token — Overall/Read plus Job/Read — cannot fetch a job's config.xml, and
nothing about how a job is defined appears anywhere else, so every job-scope
control reports MANUAL. Job/ExtendedRead makes them answerable;
Overall/Administer additionally enables the plugin and credential controls.
None of that is guessed at: what could not be read is reported as MANUAL and
left out of the score.

Credentials may be supplied by flag or environment:
  JENKINS_URL, JENKINS_USER, JENKINS_TOKEN

Use an API token rather than a password — Manage Jenkins -> People -> <user> ->
Security -> API Token.

--snapshot-out writes the captured snapshot; --snapshot-in evaluates one
already captured, with no network and no token, which is how a scan run on a
runner that holds the credentials gets re-examined later.

Exit codes: 0 clean, 1 a threshold was breached, 2 the scan failed.

Three settings drive exit 1, and they answer different questions:
  scan.failOn      are there failures this severe?
  scan.failUnder   is the score acceptable?
  scan.maxManual   did the scan see enough to have an opinion at all?

The last one matters most here. Controls that could not be evaluated are
excluded from the score rather than counted against it, so a token that can
read very little produces a high score from a small sample — and on Jenkins a
token that can read very little is the common case.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.baseURL, "url", "", "controller URL (or JENKINS_URL)")
	f.StringVar(&opts.username, "username", "", "user the API token belongs to (or JENKINS_USER)")
	f.StringVar(&opts.token, "token", "", "API token (or JENKINS_TOKEN)")
	f.StringVar(&opts.configPath, "config", "", "path to a configuration file")
	f.StringArrayVar(&opts.sets, "set", nil, "override a config key, e.g. --set scan.failOn=none")
	f.StringVar(&opts.snapshotIn, "snapshot-in", "", "evaluate a snapshot from disk instead of scanning")
	f.StringVar(&opts.snapshotOut, "snapshot-out", "", "write the captured snapshot to this path")
	f.StringVar(&opts.format, "format", report.FormatTable, "output format: "+strings.Join(report.Formats(), ", "))
	// The default table is an overview aggregated by control, so one
	// misconfiguration across fifty jobs reads as the single thing it is.
	// --details is the other question: what is wrong with *this* job.
	f.StringVar(&opts.details, "details", "", "expand to per-resource sections; --details=<resource|control>[,...] narrows them")
	f.Lookup("details").NoOptDefVal = " "
	f.BoolVar(&opts.showPassed, "show-passed", false, "include passing controls in the report")
	f.BoolVar(&opts.noRemediations, "no-remediations", false, "omit the remediation section")
	f.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour")
	return cmd
}

func runScan(cmd *cobra.Command, opts *scanOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	cfg, err := loadScanConfig(opts)
	if err != nil {
		return err
	}
	opts.scan = cfg.Scan

	if opts.format != "" && !validFormat(opts.format) {
		return fmt.Errorf("unknown format %q; use one of %s", opts.format, strings.Join(report.Formats(), ", "))
	}

	snapshot, err := obtainSnapshot(ctx, opts, cfg)
	if err != nil {
		return err
	}

	if opts.snapshotOut != "" {
		if err := writeSnapshot(opts.snapshotOut, snapshot); err != nil {
			return err
		}
	}

	eng, err := engine.New(ctx, cfg, ci.PlatformJenkins)
	if err != nil {
		return err
	}
	rep, err := eng.Evaluate(ctx, snapshot)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	renderOpts := report.Options{
		Format:         opts.format,
		Color:          !opts.noColor && isTerminal(out) && !hasNoColorEnv(),
		ShowPassed:     opts.showPassed,
		NoRemediations: opts.noRemediations,
		Details:        cmd.Flags().Changed("details"),
		DetailFilters:  splitFilters(opts.details),
		ToolVersion:    Version,
	}
	if err := report.Write(out, rep, renderOpts); err != nil {
		return err
	}

	return exitStatus(rep, opts)
}

// splitFilters turns --details=a,b into its parts, dropping the blanks a
// trailing comma leaves behind: an empty filter matches nothing, so one stray
// comma would empty the section it was meant to narrow.
func splitFilters(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func validFormat(f string) bool {
	for _, known := range report.Formats() {
		if f == known {
			return true
		}
	}
	return false
}

func loadScanConfig(opts *scanOptions) (config.Config, error) {
	path := opts.configPath
	if path == "" {
		discovered, err := config.Discover()
		if err != nil {
			return config.Config{}, err
		}
		path = discovered
	}
	cfg, err := config.LoadWithOverrides(path, opts.sets)
	if err != nil {
		return config.Config{}, err
	}
	// Validated at startup rather than at verdict time: a threshold that
	// silently inverts a control should stop the run, not change what a report
	// means without saying so.
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func obtainSnapshot(ctx context.Context, opts *scanOptions, cfg config.Config) (*ci.Snapshot, error) {
	if opts.snapshotIn != "" {
		return readSnapshot(opts.snapshotIn)
	}

	baseURL := firstNonEmpty(opts.baseURL, os.Getenv("JENKINS_URL"))
	username := firstNonEmpty(opts.username, os.Getenv("JENKINS_USER"))
	token := firstNonEmpty(opts.token, os.Getenv("JENKINS_TOKEN"))

	if baseURL == "" {
		return nil, fmt.Errorf("a controller URL is required: pass --url or set JENKINS_URL\n" +
			"or evaluate a snapshot you already have with --snapshot-in")
	}

	client, err := jenkins.NewClient(jenkins.Options{
		BaseURL:        baseURL,
		Username:       username,
		Token:          token,
		Timeout:        cfg.Scan.Timeout.Get(),
		MaxRetries:     2,
		Insecure:       cfg.Scan.Insecure,
		AllowPlaintext: cfg.Scan.AllowPlaintext,
	})
	if err != nil {
		return nil, err
	}

	fetcher := jenkins.NewFetcher(client)
	fetcher.ToolVersion = Version
	if cfg.Scan.Concurrency > 0 {
		fetcher.Concurrency = cfg.Scan.Concurrency
	}

	if cfg.Scan.MaxDuration.Get() > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Scan.MaxDuration.Get())
		defer cancel()
	}

	snapshot, err := fetcher.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func readSnapshot(path string) (*ci.Snapshot, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var snapshot ci.Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	if snapshot.SchemaVersion != "" && snapshot.SchemaVersion != ci.SchemaVersion {
		// A snapshot from a different shape is not a snapshot this build can
		// reason about, and reading it anyway would produce verdicts about
		// fields that have moved.
		return nil, fmt.Errorf("snapshot %s has schemaVersion %q; this build reads %q",
			path, snapshot.SchemaVersion, ci.SchemaVersion)
	}
	return &snapshot, nil
}

// writeSnapshot writes the snapshot with 0600 permissions.
//
// It holds no secrets by construction — see internal/ci — but it is a complete
// map of a controller's weak points, and that is worth keeping to the user who
// captured it.
func writeSnapshot(path string, snapshot *ci.Snapshot) error {
	body, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write snapshot %s: %w", path, err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// exitStatus turns a report into the process's exit code.
//
// The three conditions answer three different questions, and a scan can pass
// the first while failing the others:
//
//   - scan.failOn: are there failures this bad?
//   - scan.failUnder: is the score acceptable?
//   - scan.maxManual: did the scan actually see enough to have an opinion?
//
// The last one exists because MANUAL is excluded from both sides of the score,
// which is right in itself and perverse in aggregate: the fewer settings a
// token can read, the smaller the denominator, and the higher the score. On
// Jenkins that is not a corner case — a token without Job/ExtendedRead cannot
// answer a single job-scope control, and would otherwise score perfectly on the
// handful of controller checks it could reach.
func exitStatus(rep *engine.Report, opts *scanOptions) error {
	// A policy that could not run is a broken tool, not a finding about the
	// controller. It already degrades to MANUAL so the rest of the report
	// survives — but MANUAL leaves the score's denominator, so a bundle that
	// failed to evaluate raises the score and exits 0. That is the one outcome
	// a scan must never produce.
	if len(rep.Errors) > 0 {
		return &exitCodeError{
			code: ExitError,
			msg: fmt.Sprintf("%s could not be evaluated; the report is incomplete and its score is not comparable\n%s",
				console.Pluralize(len(rep.Errors), "control"), strings.Join(rep.Errors, "\n")),
		}
	}

	if opts.scan.MaxManual >= 0 {
		decidable := rep.Score.Passed + rep.Score.Failed + rep.Score.Manual
		if decidable > 0 {
			percent := rep.Score.Manual * 100 / decidable
			if percent > opts.scan.MaxManual {
				return &exitCodeError{
					code: ExitFindings,
					msg: fmt.Sprintf("%d%% of controls need manual review (scan.maxManual %d%%); the scan could not see enough to judge this controller\n"+
						"grant the token more read access, or raise scan.maxManual if this is expected",
						percent, opts.scan.MaxManual),
				}
			}
		}
	}

	if opts.scan.FailUnder > 0 && rep.Score.Value < opts.scan.FailUnder {
		return &exitCodeError{
			code: ExitFindings,
			msg:  fmt.Sprintf("score %d is below scan.failUnder %d", rep.Score.Value, opts.scan.FailUnder),
		}
	}

	if !strings.EqualFold(opts.scan.FailOn, "none") && rep.HasFailureAtOrAbove(opts.scan.FailOn) {
		return &exitCodeError{
			code: ExitFindings,
			msg:  failureSummary(rep, opts.scan.FailOn),
		}
	}
	return nil
}

// failureSummary describes the failures without inflating them.
//
// Score.Failed counts findings, which is one control per resource. Reporting
// that as "N controls failed" would not merely be loose: a controller with two
// hundred jobs turns one misconfigured control into two hundred findings, and
// "200 controls failed" cannot be true of a bundle that holds twenty.
func failureSummary(rep *engine.Report, threshold string) string {
	controls := map[string]bool{}
	resources := 0
	for _, f := range rep.Findings {
		if f.Status != engine.StatusFail {
			continue
		}
		if !severityAtOrAbove(f.Severity, threshold) {
			continue
		}
		controls[f.CheckID] = true
		resources++
	}
	if len(controls) == 0 {
		return "the failure threshold was breached"
	}
	summary := fmt.Sprintf("%s failed at or above %s",
		console.Pluralize(len(controls), "control"), strings.ToUpper(threshold))
	if resources > len(controls) {
		summary += fmt.Sprintf(", across %s", console.Pluralize(resources, "resource"))
	}
	return summary
}

func severityAtOrAbove(severity, threshold string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	return rank[strings.ToLower(severity)] >= rank[strings.ToLower(threshold)]
}

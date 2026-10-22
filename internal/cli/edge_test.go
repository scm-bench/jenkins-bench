package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/config"
	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// brokenWriter refuses every write, like stdout closed under the process.
type brokenWriter struct{}

var errBroken = errors.New("broken pipe")

func (brokenWriter) Write([]byte) (int, error) { return 0, errBroken }

// aFile returns the path of a regular file, for tests that need a "directory"
// that is not one.
func aFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnknownFlagsPassThroughUntouched(t *testing.T) {
	_, err := runScanCmd(t, "scan", "--no-such-flag")
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --no-such-flag") || strings.Contains(err.Error(), "config key") {
		t.Errorf("err = %v, want cobra's own unknown-flag error", err)
	}
}

func TestScanRefusesATokenWithoutItsUser(t *testing.T) {
	_, err := runScanCmd(t, "scan", "--url", "https://jenkins.invalid", "--token", "t", "--no-color")
	if err == nil || !strings.Contains(err.Error(), "--token needs the user") {
		t.Errorf("err = %v, want the missing-username refusal", err)
	}
}

func TestScanRefusesAnInvalidConfigBeforeScanning(t *testing.T) {
	_, err := runScanCmd(t, "scan", "--url", "https://jenkins.invalid", "--set", "scan.concurrency=0", "--no-color")
	if err == nil || !strings.Contains(err.Error(), "scan.concurrency") {
		t.Errorf("err = %v, want the validation error", err)
	}
}

func TestScanReportsAnUnreadableSnapshot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, err := runScanCmd(t, "scan", "--snapshot-in", missing); err == nil || !strings.Contains(err.Error(), "read snapshot") {
		t.Errorf("missing file: err = %v, want a read error", err)
	}
	garbled := filepath.Join(t.TempDir(), "garbled.json")
	if err := os.WriteFile(garbled, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", garbled); err == nil || !strings.Contains(err.Error(), "parse snapshot") {
		t.Errorf("garbled file: err = %v, want a parse error", err)
	}
}

// Every place the scan writes a file reports a failure to write it, rather
// than exiting as if the file were there.
func TestScanReportsFilesItCannotWrite(t *testing.T) {
	srv := controller(t, false)
	blocked := filepath.Join(aFile(t), "out.json") // its parent is a file
	for _, flag := range []string{"--snapshot-out", "--output-file"} {
		_, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", flag, blocked)
		if err == nil || !strings.Contains(err.Error(), "create ") {
			t.Errorf("%s into a file's subdirectory: err = %v, want a create error", flag, err)
		}
	}
}

func TestScanReportsADetailFilterThatMatchesNothing(t *testing.T) {
	srv := controller(t, false)
	_, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", "--details=no-such-job")
	if err == nil || !strings.Contains(err.Error(), "no-such-job") {
		t.Errorf("err = %v, want the filter named", err)
	}
}

func TestScanReportsAStdoutItCannotWriteTo(t *testing.T) {
	srv := controller(t, false)
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	root := NewRootCommand()
	root.SetOut(brokenWriter{})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color"})
	if err := root.Execute(); !errors.Is(err, errBroken) {
		t.Errorf("err = %v, want the writer's error", err)
	}
}

func TestListChecksReportsAnOutputItCannotWriteTo(t *testing.T) {
	root := NewRootCommand()
	root.SetOut(brokenWriter{})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"list-checks"})
	if err := root.Execute(); !errors.Is(err, errBroken) {
		t.Errorf("err = %v, want the writer's error", err)
	}
}

func TestSplitFiltersDropsBlanks(t *testing.T) {
	got := splitFilters(" legacy-build, ,CIS-2.1.6,")
	if strings.Join(got, "|") != "legacy-build|CIS-2.1.6" {
		t.Errorf("splitFilters = %q", got)
	}
}

// A policy that could not run is a broken tool, whatever else the report says.
func TestExitStatusPutsPolicyErrorsFirst(t *testing.T) {
	rep := &engine.Report{
		Errors:   []string{"CIS-2.1.6 on controller: policy produced no result"},
		Coverage: engine.Coverage{Complete: true},
	}
	err := exitStatus(rep, &scanOptions{scan: config.Default().Scan})
	if ExitCode(err) != ExitError || !strings.Contains(err.Error(), "1 control could not be evaluated") {
		t.Errorf("exitStatus = %v (code %d), want exit %d naming the control count", err, ExitCode(err), ExitError)
	}
}

func TestExitStatusEnforcesFailUnder(t *testing.T) {
	rep := &engine.Report{
		Findings: []engine.Finding{{CheckID: "CIS-2.1.6", Status: engine.StatusPass, Severity: "HIGH", Automated: true}},
		Score:    engine.Score{Value: 60, Passed: 1},
		Coverage: engine.Coverage{Complete: true},
	}
	scan := config.Default().Scan
	scan.FailOn = "none"
	scan.FailUnder = 70
	err := exitStatus(rep, &scanOptions{scan: scan})
	if ExitCode(err) != ExitFindings || !strings.Contains(err.Error(), "score 60 is below scan.failUnder 70") {
		t.Errorf("exitStatus = %v, want the failUnder breach", err)
	}
	scan.FailUnder = 60
	if err := exitStatus(rep, &scanOptions{scan: scan}); err != nil {
		t.Errorf("a score equal to failUnder passes, got %v", err)
	}
}

// A failure whose severity is not one the bundle uses still breaches the
// gate (it weighs as LOW), and the summary does not pretend to count it.
func TestFailureSummaryWithNothingItCanName(t *testing.T) {
	rep := &engine.Report{Findings: []engine.Finding{{CheckID: "X", Status: engine.StatusFail, Severity: "odd"}}}
	if got := failureSummary(rep, "low"); got != "the failure threshold was breached" {
		t.Errorf("failureSummary = %q", got)
	}
}

func TestShortRevisionKeepsAShortOneWhole(t *testing.T) {
	if got := shortRevision("abc123"); got != "abc123" {
		t.Errorf("shortRevision = %q", got)
	}
	if got := shortRevision("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("shortRevision = %q, want twelve characters", got)
	}
}

func TestIsTerminalOnAClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if isTerminal(f) {
		t.Error("a file that cannot be stat'ed is not a terminal")
	}
}

func TestWritePrivateReportsWhereItFailed(t *testing.T) {
	blocker := aFile(t)
	if err := writePrivate(filepath.Join(blocker, "sub", "r.json"), []byte("x")); err == nil || !strings.Contains(err.Error(), "create ") {
		t.Errorf("parent is a file: err = %v, want a create error", err)
	}

	orig := createTemp
	t.Cleanup(func() { createTemp = orig })

	createTemp = func(string, string) (*os.File, error) { return nil, os.ErrPermission }
	if err := writePrivate(filepath.Join(t.TempDir(), "r.json"), []byte("x")); !errors.Is(err, os.ErrPermission) {
		t.Errorf("temp file refused: err = %v, want ErrPermission", err)
	}

	// A temporary file that takes no writes — a full disk, in effect. The old
	// destination survives and the temporary file is gone.
	dir := t.TempDir()
	dest := filepath.Join(dir, "r.json")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tmpName string
	createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := orig(dir, pattern)
		if err != nil {
			return nil, err
		}
		tmpName = f.Name()
		f.Close()
		return os.Open(tmpName) // read-only
	}
	if err := writePrivate(dest, []byte("new")); err == nil || !strings.Contains(err.Error(), "write "+dest) {
		t.Fatalf("read-only temp file: err = %v, want a write error", err)
	}
	if body, _ := os.ReadFile(dest); string(body) != "old" {
		t.Errorf("destination = %q, want the old content untouched", body)
	}
	if _, err := os.Stat(tmpName); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary file %s was left behind (%v)", tmpName, err)
	}
}

func TestInitReportsWhatStopsIt(t *testing.T) {
	blocker := aFile(t)
	// Stat fails with something other than "does not exist".
	if _, err := runScanCmd(t, "init", "--path", filepath.Join(blocker, "jenkins-bench.yaml")); err == nil {
		t.Error("init under a file succeeded")
	}
	// The target does not exist, but neither does its directory.
	missingDir := filepath.Join(t.TempDir(), "absent", "jenkins-bench.yaml")
	if _, err := runScanCmd(t, "init", "--path", missingDir); err == nil || !strings.Contains(err.Error(), "write "+missingDir) {
		t.Errorf("init into a missing directory: err = %v, want a write error", err)
	}
}

func TestInitDefaultsToTheWorkingDirectory(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	out, err := runScanCmd(t, "init")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(wd, "jenkins-bench.yaml")); err != nil {
		t.Errorf("no jenkins-bench.yaml in the working directory: %v\n%s", err, out)
	}
}

func TestInitWithoutAWorkingDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux lets a process stand in a deleted directory")
	}
	wd := t.TempDir()
	gone := filepath.Join(wd, "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("os.Getwd still answers in a deleted directory here")
	}
	if _, err := runScanCmd(t, "init"); err == nil {
		t.Error("init without a working directory succeeded")
	}
}

// A bundle that fails to load is an error, not an empty list of controls.
func TestListChecksReportsABundleThatFailsToLoad(t *testing.T) {
	orig := loadChecks
	loadChecks = func() (*checks.Bundle, error) { return nil, errors.New("metadata.json: title is required") }
	t.Cleanup(func() { loadChecks = orig })
	root := NewRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"list-checks"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "title is required") {
		t.Errorf("err = %v, want the load error", err)
	}
}

package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci/jenkins"
)

func sent(method, path string, status int) jenkins.RequestEvent {
	return jenkins.RequestEvent{Method: method, Path: path, Status: status, Took: 12 * time.Millisecond}
}

// The closing line is the reason the tracer exists: the operator handed over a
// token that can read every job configuration, and this is where they are told
// what it was used for.
func TestSummaryAccountsForEveryRequest(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	for i := 0; i < 59; i++ {
		tr.record(sent(http.MethodGet, "/api/json", 200))
	}
	summary, tag := tr.summary()
	if summary != "✓ 59 requests · 59 GET · 0 writes · read-only" {
		t.Errorf("summary = %q", summary)
	}
	if tag.Text != "INFO" {
		t.Errorf("tag = %v, want INFO", tag)
	}
}

// The count comes from the requests that were sent, not from the promise that
// they are all GET. If that ever stops being true, this is what says so.
func TestSummaryFlagsANonReadRequest(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	tr.record(sent(http.MethodGet, "/api/json", 200))
	tr.record(sent(http.MethodPost, "/job/x/build", 201))
	summary, tag := tr.summary()
	if strings.Contains(summary, "read-only") {
		t.Errorf("summary = %q must not claim read-only after a POST", summary)
	}
	for _, want := range []string{"✗", "1 POST", "NOT READ-ONLY"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary = %q, missing %q", summary, want)
		}
	}
	if tag.Text != "FAIL" {
		t.Errorf("tag = %v, want FAIL", tag)
	}
}

func TestSummaryIsEmptyWhenNothingWasSent(t *testing.T) {
	if s, _ := newTracer(&bytes.Buffer{}, false, false).summary(); s != "" {
		t.Errorf("summary = %q, want nothing when no request was made", s)
	}
}

func TestSummaryCountsRetries(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, false)
	tr.record(sent(http.MethodGet, "/api/json", 503))
	retry := sent(http.MethodGet, "/api/json", 200)
	retry.Attempt = 1
	tr.record(retry)
	if s, _ := tr.summary(); !strings.Contains(s, "2 requests · 2 GET · 1 retried · 0 writes") {
		t.Errorf("summary = %q, want the retry counted among the requests", s)
	}
}

// --verbose prints a line per request as it completes; without it the tracer
// only counts.
func TestVerboseTracePrintsEachRequest(t *testing.T) {
	var out bytes.Buffer
	tr := newTracer(&out, false, true)
	tr.record(sent(http.MethodGet, "/api/json?tree=useSecurity", 200))
	tr.record(sent(http.MethodGet, "/job/a/config.xml", 403))
	failed := sent(http.MethodGet, "/computer/api/json", 0)
	failed.Err = errors.New("connection reset")
	tr.record(failed)
	retried := sent(http.MethodGet, "/pluginManager/api/json", 503)
	retried.Attempt = 2
	retried.Took = 1500 * time.Millisecond
	tr.record(retried)

	got := out.String()
	for _, want := range []string{"[INFO]", "GET  /api/json?tree=useSecurity", "200", "403", "err", "connection reset", "retry 2", "1.5s"} {
		if !strings.Contains(got, want) {
			t.Errorf("trace is missing %q:\n%s", want, got)
		}
	}
	if lines := strings.Count(got, "\n"); lines != 4 {
		t.Errorf("trace has %d lines, want one per request:\n%s", lines, got)
	}

	var quiet bytes.Buffer
	silent := newTracer(&quiet, false, false)
	silent.record(sent(http.MethodGet, "/api/json", 200))
	if quiet.Len() != 0 {
		t.Errorf("without --verbose nothing is printed per request:\n%s", quiet.String())
	}
}

// Colour is reinforcement, never the only signal: the text survives without it.
func TestTraceColourIsOptional(t *testing.T) {
	var out bytes.Buffer
	tr := newTracer(&out, true, true)
	tr.record(sent(http.MethodPost, "/x", 500))
	if !strings.Contains(out.String(), "\033[") {
		t.Error("colour was requested and not applied")
	}
	summary, _ := tr.summary()
	if !strings.Contains(summary, "NOT READ-ONLY") {
		t.Errorf("summary = %q", summary)
	}
}

// Every scan that contacted the controller ends its trace with the account of
// what was sent — without -v too, because that is the run a CI log keeps.
func TestScanAccountsForItsRequests(t *testing.T) {
	srv := controller(t, false)
	_, stderr, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, " GET · 0 writes · read-only") || !strings.Contains(stderr, "✓ ") {
		t.Errorf("no accounting line:\n%s", stderr)
	}
	if strings.Contains(stderr, "/api/json?tree=") {
		t.Errorf("without -v no request is printed:\n%s", stderr)
	}

	_, verbose, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", "-v")
	if err != nil {
		t.Fatalf("scan -v: %v", err)
	}
	for _, want := range []string{"GET  /api/json?tree=useSecurity", "/job/app/config.xml", "0 writes · read-only"} {
		if !strings.Contains(verbose, want) {
			t.Errorf("-v trace is missing %q:\n%s", want, verbose)
		}
	}
}

// A scan of a snapshot on disk contacted nobody, and says nothing about
// requests.
func TestOfflineScanHasNoAccountingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"2","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true,"jobs":true}},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, _ := runScanSplit(t, "scan", "--snapshot-in", path)
	if strings.Contains(stderr, "requests") {
		t.Errorf("an offline scan sent nothing:\n%s", stderr)
	}
}

// A scan that failed to complete still accounts for what it sent first.
func TestFailedScanStillAccountsForItsRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, stderr, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "wrong", "--no-color")
	if err == nil {
		t.Fatal("a rejected token must fail the scan")
	}
	if !strings.Contains(stderr, "0 writes · read-only") {
		t.Errorf("the requests sent before the failure should still be accounted for:\n%s", stderr)
	}
}

// Progress only ever goes to a terminal, so the writer is nil for everything
// else, and nil has to be inert.
func TestProgressIsOnlyForATerminal(t *testing.T) {
	var buf bytes.Buffer
	if p := newProgressWriter(&buf, true); p != nil {
		t.Error("a non-terminal writer should get no progress")
	}
	if p := newProgressWriter(os.Stderr, false); p != nil {
		t.Error("disabled progress returned a writer")
	}
	var p *progressWriter
	p.start()
	p.tick()
	p.jobsRead(1, 2)
	ran := false
	p.interrupt(func() { ran = true })
	p.clear()
	if !ran {
		t.Error("interrupt on a nil writer must still print")
	}
}

func TestProgressOverwritesInPlaceAndStepsAsideForWarnings(t *testing.T) {
	var buf bytes.Buffer
	p := &progressWriter{out: &buf}
	p.start()
	p.tick()
	p.jobsRead(3, 10)
	p.interrupt(func() { buf.WriteString("[WARN] something\n") })
	p.jobsRead(4, 10)
	p.clear()

	got := buf.String()
	for _, want := range []string{"reading jobs 3/10 · 1 requests", "[WARN] something\n", "reading jobs 4/10"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress output is missing %q:\n%q", want, got)
		}
	}
	// The warning starts on an erased line, not after the status text.
	if strings.Contains(got, "10 · 1 requests[WARN]") {
		t.Errorf("the warning was printed onto the status line:\n%q", got)
	}
	if !strings.HasSuffix(got, "\r") {
		t.Errorf("clear should leave the cursor at the start of an erased line:\n%q", got)
	}
}

// scan.progress: full prints every request without -v; off prints none of
// them, and the closing account still.
func TestProgressSettingDecidesWhatIsPrinted(t *testing.T) {
	srv := controller(t, false)
	_, full, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", "--set", "scan.progress=full")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full, "GET  /api/json?tree=useSecurity") {
		t.Errorf("progress full should print every request:\n%s", full)
	}
	_, off, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", "--set", "scan.progress=off")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "GET  /") || !strings.Contains(off, "0 writes · read-only") {
		t.Errorf("progress off prints no request and still accounts for them:\n%s", off)
	}
	// -v was typed just now and wins over the file.
	_, verbose, _ := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color", "--set", "scan.progress=off", "-v")
	if !strings.Contains(verbose, "GET  /api/json?tree=useSecurity") {
		t.Errorf("-v should override progress off:\n%s", verbose)
	}
}

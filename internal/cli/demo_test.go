package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// The demo exists for the reader who has nothing configured yet, so it must
// work from a bare binary: no controller, no checkout, no flags beyond the one.
func TestDemoEvaluatesTheBundledExample(t *testing.T) {
	stdout, stderr, err := runScanSplit(t, "scan", "--demo", "-o", "json", "--set", "scan.failOn=none")
	if code := ExitCode(err); code != ExitOK {
		t.Fatalf("exit code = %d (%v), want %d\n%s", code, err, ExitOK, stderr)
	}
	var rep struct {
		Findings []struct {
			Status string `json:"status"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the demo produced no findings, so it demonstrates nothing")
	}
	// The stderr line is what stays on the terminal when stdout is redirected.
	if !strings.Contains(stderr, "bundled example") {
		t.Errorf("stderr never says the scan was a demo:\n%s", stderr)
	}
}

// The table must say it is example data where the eye lands first; a real
// report must never carry that banner.
func TestDemoTableIsMarkedAsExampleData(t *testing.T) {
	stdout, _, _ := runScanSplit(t, "scan", "--demo", "--no-color")
	if !strings.Contains(stdout, "EXAMPLE DATA") {
		t.Errorf("table output carries no example-data banner:\n%s", stdout)
	}
	real, _, _ := runScanSplit(t, "scan", "--snapshot-in", examplePath(t, "snapshot.json"), "--no-color")
	if strings.Contains(real, "EXAMPLE DATA") {
		t.Error("a snapshot scan was marked as example data")
	}
}

// The demo demonstrates the whole contract, exit code included: the sample
// carries HIGH failures, so under the default failOn it exits 1.
func TestDemoHonoursTheExitCodeContract(t *testing.T) {
	_, _, err := runScanSplit(t, "scan", "--demo", "--no-color")
	if code := ExitCode(err); code != ExitFindings {
		t.Errorf("exit code = %d (%v), want %d for the sample's HIGH failures", code, err, ExitFindings)
	}
}

func TestDemoRejectsFlagsItWouldIgnore(t *testing.T) {
	for _, args := range [][]string{
		{"--url", "https://example.invalid"},
		{"--username", "u"},
		{"--token", "t"},
		{"--folder", "platform"},
		{"--job", "app"},
		{"--snapshot-in", "x.json"},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, _, err := runScanSplit(t, append([]string{"scan", "--demo"}, args...)...)
			if code := ExitCode(err); code != ExitError {
				t.Errorf("exit code = %d (%v), want %d", code, err, ExitError)
			}
		})
	}
}

// An exported JENKINS_URL must neither break the demo nor leak into it.
func TestDemoIgnoresInheritedCredentials(t *testing.T) {
	t.Setenv("JENKINS_BENCH_CONFIG_DIR", t.TempDir())
	t.Setenv("JENKINS_URL", "https://stale.example.com")
	t.Setenv("JENKINS_USER", "stale")
	t.Setenv("JENKINS_TOKEN", "stale")
	var out strings.Builder
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&strings.Builder{})
	root.SetArgs([]string{"scan", "--demo", "-o", "json", "--set", "scan.failOn=none"})
	if err := root.Execute(); ExitCode(err) != ExitOK {
		t.Fatalf("exit code = %d (%v); an exported JENKINS_URL must not break the demo", ExitCode(err), err)
	}
	if strings.Contains(out.String(), "stale.example.com") {
		t.Error("the environment's URL leaked into the demo report")
	}
}

// With nothing configured, the error is the reader's first contact with the
// tool, so it lists every way out, the demo included.
func TestMissingControllerErrorNamesTheDemo(t *testing.T) {
	_, _, err := runScanSplit(t, "scan", "--no-color")
	if err == nil || !strings.Contains(err.Error(), "scan --demo") {
		t.Errorf("the error does not mention --demo: %v", err)
	}
}

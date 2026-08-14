package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/ci"
	"github.com/scm-bench/jenkins-bench/internal/config"
)

// examplePath resolves a file under examples/ from this package's directory.
func examplePath(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "examples", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("examples/%s is missing, and .goreleaser.yaml ships examples/* in every archive: %v", name, err)
	}
	return path
}

// The sample config is what a reader copies. A key that no longer exists, or a
// default that has drifted, teaches them something untrue — and this is the
// only thing that would notice.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := config.Load(examplePath(t, "config.yaml"))
	if err != nil {
		t.Fatalf("examples/config.yaml does not load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("examples/config.yaml does not validate: %v", err)
	}
}

// Every value in the sample is stated as the default, so the file documents the
// defaults rather than quietly changing them for anyone who copies it.
func TestExampleConfigMatchesTheDefaults(t *testing.T) {
	cfg, err := config.Load(examplePath(t, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := config.Default()
	if cfg.Scan != want.Scan {
		t.Errorf("scan section differs from the defaults:\n got %+v\nwant %+v", cfg.Scan, want.Scan)
	}
	if cfg.Thresholds != want.Thresholds {
		t.Errorf("thresholds differ from the defaults:\n got %+v\nwant %+v", cfg.Thresholds, want.Thresholds)
	}
	if cfg.SkipDisabledJobs != want.SkipDisabledJobs {
		t.Errorf("skipDisabledJobs = %v, want the default %v", cfg.SkipDisabledJobs, want.SkipDisabledJobs)
	}
}

func TestExampleSnapshotIsCurrent(t *testing.T) {
	body, err := os.ReadFile(examplePath(t, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap ci.Snapshot
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snap); err != nil {
		t.Fatalf("examples/snapshot.json has a field this build does not know: %v", err)
	}
	if snap.SchemaVersion != ci.SchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", snap.SchemaVersion, ci.SchemaVersion)
	}
	if snap.Metadata.Platform != ci.PlatformJenkins {
		t.Errorf("platform = %q", snap.Metadata.Platform)
	}
}

// The sample exists to show what a report looks like, so it has to contain
// something to report. A snapshot of a perfect controller would render an empty
// findings table and teach nobody anything.
func TestExampleSnapshotShowsAMixedPosture(t *testing.T) {
	out, err := runScanCmd(t, "scan",
		"--snapshot-in", examplePath(t, "snapshot.json"),
		"--config", examplePath(t, "config.yaml"),
		"--no-color")
	if err == nil {
		t.Error("the sample should produce findings, and therefore a non-zero exit")
	} else if code := ExitCode(err); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	if !strings.Contains(out, "SCORE") {
		t.Errorf("no report:\n%s", out)
	}
}

// The whole snapshot must survive a round trip through the reader, including
// the job whose configuration could not be read — that entry is the one a
// reader learns most from, and the easiest to drop by accident.
func TestExampleSnapshotKeepsUnreadableJobs(t *testing.T) {
	body, err := os.ReadFile(examplePath(t, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap ci.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatal(err)
	}

	var unreadable, disabled, multibranch int
	for _, job := range snap.Jobs {
		if !job.Available["config"] {
			unreadable++
			if len(job.Errors) == 0 {
				t.Errorf("%s is unreadable but records no reason", job.FullName)
			}
		}
		if job.Disabled {
			disabled++
		}
		if job.Kind == ci.KindMultibranch {
			multibranch++
		}
	}
	if unreadable == 0 {
		t.Error("the sample should include a job whose configuration could not be read")
	}
	if disabled == 0 {
		t.Error("the sample should include a disabled job, for the NA path")
	}
	if multibranch == 0 {
		t.Error("the sample should include a multibranch project")
	}
}

// A snapshot is written to disk and passed around, and this one is checked into
// a public repository.
//
// The check is on keys and on shapes, not on the word "password": a credential's
// type is legitimately "Username with password", and a substring search flags
// that while missing an actual secret stored under an innocent name.
func TestExampleSnapshotHoldsNoSecrets(t *testing.T) {
	body, err := os.ReadFile(examplePath(t, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}

	// No key the snapshot schema does not define. A secret can only get in
	// under a name, and every legal name is known.
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"authToken", "password", "secret", "script", "apiToken", "privateKey"}
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				for _, bad := range forbidden {
					if strings.EqualFold(key, bad) {
						t.Errorf("%s.%s: a snapshot must not carry this field", path, key)
					}
				}
				walk(child, path+"."+key)
			}
		case []any:
			for i, child := range v {
				walk(child, path)
				_ = i
			}
		case string:
			// Jenkins encrypts most stored secrets as {AQAAABAAAA…}, and PEM
			// blocks and long opaque strings are the other two shapes worth
			// refusing outright.
			if strings.HasPrefix(v, "{AQAAAB") || strings.Contains(v, "-----BEGIN") {
				t.Errorf("%s carries what looks like a secret", path)
			}
		}
	}
	walk(raw, "$")
}

// init writes the same file examples/config.yaml holds — the one the README
// points at. Two copies of a commented reference config is one copy too many,
// and the way that goes wrong is silently.
func TestInitWritesTheSampleConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "jenkins-bench.yaml")

	if _, err := runScanCmd(t, "init", "--path", target); err != nil {
		t.Fatalf("init: %v", err)
	}

	written, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(examplePath(t, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(onDisk) {
		t.Error("init wrote something other than examples/config.yaml")
	}

	// And what it wrote has to be loadable, or init hands people a broken file.
	cfg, err := config.Load(target)
	if err != nil {
		t.Fatalf("the file init wrote does not load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the file init wrote does not validate: %v", err)
	}
}

// As likely to be run by a script as by a person, so overwriting a tuned
// configuration should not happen on a typo.
func TestInitRefusesToOverwrite(t *testing.T) {
	target := filepath.Join(t.TempDir(), "jenkins-bench.yaml")
	if err := os.WriteFile(target, []byte("scan:\n  failOn: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runScanCmd(t, "init", "--path", target)
	if err == nil {
		t.Fatal("init overwrote an existing file")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the error should say how to proceed: %v", err)
	}

	body, _ := os.ReadFile(target)
	if !strings.Contains(string(body), "failOn: none") {
		t.Error("the existing file was modified")
	}

	if _, err := runScanCmd(t, "init", "--path", target, "--force"); err != nil {
		t.Fatalf("--force should overwrite: %v", err)
	}
}

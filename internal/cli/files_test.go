package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWritePrivateReplacesWholeAndTightens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "report.json")
	if err := writePrivate(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "second" {
		t.Errorf("content = %q", body)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600 even over a 0644 file", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files were left behind: %v", entries)
	}
}

// A write that cannot complete leaves what was there, and no temporary file.
func TestWritePrivateLeavesNothingBehindOnFailure(t *testing.T) {
	dir := t.TempDir()
	// The destination is a directory: the rename onto it fails.
	target := filepath.Join(dir, "occupied")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(target, []byte("x")); err == nil {
		t.Fatal("renaming over a directory should fail")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// --output-file puts the report in a file, 0600, and nothing on stdout.
func TestOutputFileWritesThePrivateReport(t *testing.T) {
	srv := controller(t, false)
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runScanCmd(t, "scan", "--url", srv.URL, "--username", "u", "--token", "t",
		"-o", "sarif", "--output-file", path)
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	if strings.Contains(out, `"$schema"`) {
		t.Errorf("the report went to stdout as well:\n%s", out)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"version": "2.1.0"`) {
		t.Errorf("the file does not hold the SARIF report:\n%s", body)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("report mode = %o, want 600", info.Mode().Perm())
		}
	}
}

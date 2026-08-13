package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The whole feature is "the next run does not ask": what SaveInstance writes,
// LoadInstance must hand back.
func TestInstanceRoundTrips(t *testing.T) {
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", t.TempDir())

	saved := Instance{URL: "https://bitbucket.example.com", Token: "sekrit"}
	path, err := SaveInstance(saved)
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, loadedPath, err := LoadInstance()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded != saved {
		t.Errorf("loaded %+v, want %+v", loaded, saved)
	}
	if loadedPath != path {
		t.Errorf("load path %q, save path %q", loadedPath, path)
	}
}

// The file holds a live credential, so it gets the permissions the snapshot
// gets, for a stronger version of the same reason.
func TestSavedInstanceIsOwnerOnly(t *testing.T) {
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", t.TempDir())

	path, err := SaveInstance(Instance{URL: "https://x", Token: "t"})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced on Windows; see the README note")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("instance file permissions = %o, want 600", perm)
	}
}

// Nothing saved is the normal first-run state, not a failure.
func TestLoadInstanceAbsentIsNotAnError(t *testing.T) {
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", t.TempDir())

	inst, path, err := LoadInstance()
	if err != nil {
		t.Fatalf("load with nothing saved: %v", err)
	}
	if inst != (Instance{}) {
		t.Errorf("absent file produced %+v", inst)
	}
	if path == "" {
		t.Error("the path is reported even when nothing is there yet")
	}
}

// A file that exists but cannot be understood is an error, not an anonymous
// scan: `tokn:` parsing cleanly to an instance with no token would send the
// user to debug permissions instead of a typo.
func TestLoadInstanceRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "instance.yaml"),
		[]byte("url: https://x\ntokn: oops\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, err := LoadInstance(); err == nil {
		t.Error("a misspelled key was silently ignored")
	}
}

// BITBUCKET_BENCH_CONFIG_DIR is both the pipeline's pin and the test suite's
// isolation, so it has to actually win over the platform directory. The
// expectation is built with filepath.Join rather than a literal, because the
// separator is the platform's — a hard-coded /pinned/elsewhere passed on Unix
// and failed on Windows without testing anything different.
func TestInstancePathHonoursTheOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", dir)

	path, err := InstancePath()
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if want := filepath.Join(dir, "instance.yaml"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

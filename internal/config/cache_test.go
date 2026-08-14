package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSnapshotCachePathNamesTheHost(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", dir)

	path, err := SnapshotCachePath("https://Bitbucket.Example.com:7990/context")
	if err != nil {
		t.Fatalf("SnapshotCachePath: %v", err)
	}
	want := filepath.Join(dir, "cache", "bitbucket.example.com_7990.json")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "cache"))
		if err != nil {
			t.Fatalf("stat cache dir: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("cache directory mode = %o, want 0700", perm)
		}
	}
}

func TestSnapshotCachePathSurvivesAnUnparseableURL(t *testing.T) {
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", t.TempDir())

	path, err := SnapshotCachePath("::not a url::")
	if err != nil {
		t.Fatalf("SnapshotCachePath: %v", err)
	}
	if got := filepath.Base(path); got != "__not_a_url__.json" {
		t.Errorf("file name = %q, want the sanitized raw string", got)
	}
}

func TestLatestSnapshotCachePicksTheNewest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BITBUCKET_BENCH_CONFIG_DIR", dir)

	// Before any scan there is nothing — not even the directory — and that
	// is a "" answer, not an error.
	if path, err := LatestSnapshotCache(); err != nil || path != "" {
		t.Fatalf("empty cache: path = %q, err = %v; want \"\" and nil", path, err)
	}

	older, err := SnapshotCachePath("https://old.example.com")
	if err != nil {
		t.Fatalf("SnapshotCachePath: %v", err)
	}
	newer, err := SnapshotCachePath("https://new.example.com")
	if err != nil {
		t.Fatalf("SnapshotCachePath: %v", err)
	}
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatalf("age %s: %v", older, err)
	}
	// A stray non-snapshot file must not be mistaken for one.
	if err := os.WriteFile(filepath.Join(dir, "cache", "README"), []byte("not a snapshot"), 0o600); err != nil {
		t.Fatalf("write stray file: %v", err)
	}

	got, err := LatestSnapshotCache()
	if err != nil {
		t.Fatalf("LatestSnapshotCache: %v", err)
	}
	if got != newer {
		t.Errorf("latest = %q, want %q", got, newer)
	}
}

func TestScanCacheSetting(t *testing.T) {
	if !Default().Scan.Cache {
		t.Error("the snapshot cache should default to on")
	}

	path := filepath.Join(t.TempDir(), "jenkins-bench.yaml")
	if err := os.WriteFile(path, []byte("scan:\n  cache: false\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Cache {
		t.Error("scan.cache: false in the file did not turn the cache off")
	}

	cfg, err = LoadWithOverrides("", []string{"scan.cache=false"})
	if err != nil {
		t.Fatalf("LoadWithOverrides: %v", err)
	}
	if cfg.Scan.Cache {
		t.Error("--set scan.cache=false did not turn the cache off")
	}
}

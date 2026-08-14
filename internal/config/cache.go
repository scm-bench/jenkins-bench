package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The snapshot cache: every successful network scan leaves its snapshot in
// this directory so a later `scan --last` can re-render it without another
// fetch. It lives under the config directory rather than the platform cache
// directory on purpose: a snapshot is a map of the instance's weak points,
// not disposable derived data; BITBUCKET_BENCH_CONFIG_DIR already pins this
// location for tests and pipelines; and deleting one directory must be
// enough to forget everything jenkins-bench has written down.
const cacheDirName = "cache"

// SnapshotCachePath is where a scan of baseURL caches its snapshot: one file
// per host, so alternating between instances never records one instance's
// posture under the other's name. It creates the cache directory 0700 — the
// listing alone says which instances someone audits.
func SnapshotCachePath(baseURL string) (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, cacheDirName)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", cacheDir, err)
	}
	return filepath.Join(cacheDir, cacheFileName(baseURL)), nil
}

// cacheFileName reduces a base URL to a filename: the lowercased host and
// port, with anything a filesystem might object to replaced. The URL was
// good enough to scan with by the time this runs, so a parse failure falls
// back to sanitizing the raw string rather than failing the write.
func cacheFileName(baseURL string) string {
	host := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		host = u.Host
	}
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, host)
	return sanitized + ".json"
}

// LatestSnapshotCache returns the most recently written cached snapshot, or
// "" when there is none — the normal state before any scan has run, not an
// error.
func LatestSnapshotCache() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, cacheDirName)
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read snapshot cache %s: %w", cacheDir, err)
	}
	var newest string
	var newestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest, newestMod = filepath.Join(cacheDir, entry.Name()), info.ModTime()
		}
	}
	return newest, nil
}

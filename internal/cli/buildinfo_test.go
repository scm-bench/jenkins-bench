package cli

import (
	"runtime/debug"
	"strings"
	"testing"
)

// withBuildInfo runs resolveBuildInfo against a synthetic build info, with the
// package-level values restored afterwards.
func withBuildInfo(t *testing.T, version string, settings map[string]string, ldflags [3]string) (string, string, string) {
	t.Helper()

	savedV, savedC, savedD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = savedV, savedC, savedD })

	Version, Commit, Date = ldflags[0], ldflags[1], ldflags[2]

	info := &debug.BuildInfo{Main: debug.Module{Version: version}}
	for k, v := range settings {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	resolveBuildInfo(func() (*debug.BuildInfo, bool) { return info, true })

	return Version, Commit, Date
}

var unset = [3]string{unsetVersion, unsetCommit, unsetDate}

// `go install module@version` fetches through the proxy: the version is real,
// and there is no repository to stamp a revision from.
func TestModuleVersionIsUsedWhenThereIsNoVCSStamp(t *testing.T) {
	v, c, d := withBuildInfo(t, "v0.1.0", nil, unset)

	if v != "v0.1.0" {
		t.Errorf("Version = %q, want the module version", v)
	}
	// Absent information must stay absent rather than being invented.
	if c != unsetCommit || d != unsetDate {
		t.Errorf("commit/date = %q/%q, want them left unset", c, d)
	}
}

// A build from a checkout has no module version but does stamp the revision.
func TestRevisionIsUsedWhenThereIsNoModuleVersion(t *testing.T) {
	v, c, d := withBuildInfo(t, "(devel)", map[string]string{
		"vcs.revision": "0c6587bef4f7318baad8dc28fb7937f564b69941",
		"vcs.time":     "2026-08-10T05:39:22Z",
		"vcs.modified": "false",
	}, unset)

	if v != "devel-0c6587bef4f7" {
		t.Errorf("Version = %q, want a short revision", v)
	}
	if c != "0c6587bef4f7318baad8dc28fb7937f564b69941" {
		t.Errorf("Commit = %q, want the full revision", c)
	}
	if d != "2026-08-10T05:39:22Z" {
		t.Errorf("Date = %q, want the commit time", d)
	}
}

// A dirty tree means the revision does not describe what was compiled.
func TestDirtyTreeIsReported(t *testing.T) {
	v, c, _ := withBuildInfo(t, "(devel)", map[string]string{
		"vcs.revision": "0c6587bef4f7318baad8dc28fb7937f564b69941",
		"vcs.modified": "true",
	}, unset)

	if !strings.HasSuffix(v, "-dirty") {
		t.Errorf("Version = %q, want a dirty marker", v)
	}
	if !strings.Contains(c, "dirty") {
		t.Errorf("Commit = %q, want a dirty marker", c)
	}
}

// The toolchain's own pseudo-version already ends in "+dirty". Appending a
// second marker reads like a bug, and did before this was handled.
func TestDirtyMarkerIsNotDoubled(t *testing.T) {
	v, _, _ := withBuildInfo(t, "v0.1.0-rc.2.0.20260810052717-596e0e245c26+dirty", map[string]string{
		"vcs.revision": "596e0e245c26a7b30ffa9b91c2d1f01770ce90e4",
		"vcs.modified": "true",
	}, unset)

	if n := strings.Count(v, "dirty"); n != 1 {
		t.Errorf("Version = %q contains %d dirty markers, want 1", v, n)
	}
}

// A release build passed real values through -ldflags. Nothing here may
// second-guess them.
func TestLdflagsAreNeverOverwritten(t *testing.T) {
	v, c, d := withBuildInfo(t, "v9.9.9", map[string]string{
		"vcs.revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"vcs.time":     "2020-01-01T00:00:00Z",
		"vcs.modified": "true",
	}, [3]string{"v0.1.0", "deadbeef", "2026-08-10T00:00:00Z"})

	if v != "v0.1.0" || c != "deadbeef" || d != "2026-08-10T00:00:00Z" {
		t.Errorf("ldflag values were overwritten: %q %q %q", v, c, d)
	}
}

// A binary with no build info at all — the values simply stay as they are.
func TestMissingBuildInfoLeavesDefaults(t *testing.T) {
	savedV, savedC, savedD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = savedV, savedC, savedD })
	Version, Commit, Date = unsetVersion, unsetCommit, unsetDate

	resolveBuildInfo(func() (*debug.BuildInfo, bool) { return nil, false })

	if Version != unsetVersion || Commit != unsetCommit || Date != unsetDate {
		t.Errorf("values changed without build info: %q %q %q", Version, Commit, Date)
	}
}

func TestIsReleaseVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.1.0":      true,
		"v0.1.0-rc.1": true,
		"(devel)":     false,
		"":            false,
		"(unknown)":   false,
	} {
		if got := isReleaseVersion(v); got != want {
			t.Errorf("isReleaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

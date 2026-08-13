package cli

import (
	"runtime/debug"
	"strings"
)

// Version metadata. A release build sets these through -ldflags; anything else
// leaves them at the sentinels below and they are filled in from what the Go
// toolchain already embedded.
var (
	Version = unsetVersion
	Commit  = unsetCommit
	Date    = unsetDate
)

// The values the linker overwrites. They are compared against rather than
// assumed, so a build that did set them is never second-guessed.
const (
	unsetVersion = "dev"
	unsetCommit  = "none"
	unsetDate    = "unknown"
)

func init() { resolveBuildInfo(debug.ReadBuildInfo) }

// resolveBuildInfo fills in whatever -ldflags did not.
//
// This matters past the version command. The tool version is stamped into
// every report and into every snapshot, and a snapshot is meant to be
// re-evaluated later — an archive that says it was produced by "dev" cannot be
// traced to the code that produced it, which is a poor showing for something
// whose whole argument is that its output should be checkable.
//
// The two install paths carry different halves of the answer, and neither is
// wrong:
//
//   - `go install module@version` fetches through the module proxy, so there is
//     no repository to read: Main.Version is the real version, and there is no
//     VCS stamp at all.
//   - `go build`/`go install ./...` inside a checkout reports Main.Version as
//     "(devel)" — the module has no version yet — but does stamp the revision,
//     its time, and whether the tree was dirty.
func resolveBuildInfo(read func() (*debug.BuildInfo, bool)) {
	info, ok := read()
	if !ok {
		return
	}

	settings := make(map[string]string, len(info.Settings))
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	revision := settings["vcs.revision"]
	dirty := settings["vcs.modified"] == "true"

	if Version == unsetVersion {
		switch {
		case isReleaseVersion(info.Main.Version):
			Version = info.Main.Version
		case revision != "":
			// No version to report, but the revision identifies the build
			// exactly, which is the useful half of what a version is for.
			Version = "devel-" + shortRevision(revision)
		}
		// A dirty tree means the revision does not describe what was compiled,
		// which is worth saying — but the toolchain's own pseudo-version
		// already ends in "+dirty", and saying it twice reads like a bug.
		if dirty && Version != unsetVersion && !strings.Contains(Version, "dirty") {
			Version += "-dirty"
		}
	}

	if Commit == unsetCommit && revision != "" {
		Commit = revision
		if dirty {
			Commit += " (dirty)"
		}
	}

	if Date == unsetDate && settings["vcs.time"] != "" {
		Date = settings["vcs.time"]
	}
}

// isReleaseVersion reports whether the module version names an actual release
// rather than a placeholder. "(devel)" is what the toolchain reports for a
// module built from a checkout with no version of its own.
func isReleaseVersion(v string) bool {
	return v != "" && v != "(devel)" && !strings.HasPrefix(v, "(")
}

func shortRevision(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

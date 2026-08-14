// Package checks embeds the policy bundle: one directory per control, each
// holding a Rego module that makes the decision and a metadata.json that
// describes it. Adding a control means adding a directory — no Go code changes.
package checks

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Only the files the bundle is made of, named explicitly.
//
// `all:policies` would sweep in the *_test.rego files that sit beside each
// rule. The loader skips them, so nothing would misbehave — but they would
// still be compiled into every released binary, and a tool whose argument is
// that its output should be checkable ought not to ship a binary containing
// rules named test_fails_when_nothing_restricts_the_default_branch for someone
// to find and wonder about.
//
// A new platform directory is picked up by the wildcards. A new file under
// lib/ is not, and has to be added here — which announces itself immediately,
// because any rule importing it fails to compile the moment Load runs.
//
//go:embed policies/lib/common.rego
//go:embed policies/*/*/check.rego
//go:embed policies/*/*/metadata.json
var policiesFS embed.FS

// Severity levels, ordered by the weight they carry in the score.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
)

// Scopes a check can be evaluated against.
//
// These belong to this bench, not to the family. The generic metadata schema
// requires only that a control says what it is about; which words are legal is
// a question about a domain, and it is answered here — and enforced by
// validate(), because a typo in a scope would otherwise silently produce a
// control that is never evaluated against anything.
const (
	// ScopeController evaluates a control once, against the instance.
	ScopeController = "controller"
	// ScopeJob evaluates a control once per job.
	ScopeJob = "job"
)

// Weight is the score contribution of a severity level.
func Weight(severity string) int {
	switch strings.ToUpper(severity) {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 1
	}
}

// Metadata describes one control. It is the single source of truth for what a
// report says about a finding, including the remediation text.
type Metadata struct {
	// ID is the check identifier used on the command line, e.g. "CIS-1.1.3".
	ID string `json:"id"`
	// CISID is the bare benchmark number, e.g. "1.1.3".
	CISID string `json:"cisId"`
	// Package is the Rego package that decides this check.
	Package string `json:"package"`
	// Scope selects what the check is evaluated against.
	Scope string `json:"scope"`
	// Severity is HIGH, MEDIUM or LOW.
	Severity string `json:"severity"`
	// Platforms lists the SCM platforms this check applies to.
	Platforms []string `json:"platforms"`
	// Automated is false for controls that no API can answer, which always
	// report MANUAL and never affect the score.
	Automated bool `json:"automated"`

	Title       string `json:"title"`
	Description string `json:"description"`
	// Remediation names the exact UI path an operator has to walk. This is the
	// part of a finding that actually gets acted on, so it stays concrete.
	Remediation string `json:"remediation"`
	// FixSummary is Remediation's first move, in one imperative line: the thing
	// to do, and where. Remediation keeps the rest — the project-wide variant,
	// the exemptions worth granting, the config key that changes what the
	// control counts — because that is a paragraph, and a paragraph under every
	// verdict is what turned this report into prose you had to read to find the
	// next finding. The summary rides with the verdict; the paragraph waits in
	// its own section.
	FixSummary string   `json:"fixSummary"`
	References []string `json:"references,omitempty"`
}

// Check couples metadata with the directory it was loaded from.
type Check struct {
	Metadata
	Dir string
}

// Module is one Rego source file.
type Module struct {
	Path   string
	Source string
}

// Bundle is the loaded policy set.
type Bundle struct {
	Checks  []Check
	Modules []Module
}

// Load parses the embedded policy bundle and validates every control.
func Load() (*Bundle, error) {
	bundle := &Bundle{}
	seen := map[string]string{}

	err := fs.WalkDir(policiesFS, "policies", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch path.Ext(p) {
		case ".rego":
			// Rego unit tests live beside the rules they test, the same way Go
			// tests do and the way `opa test` expects to find them, so adding a
			// control still means adding one directory. They are not part of
			// the bundle: compiling them into the engine would put assertion
			// rules in the same namespace as verdicts, and `opa test` is what
			// runs them.
			if strings.HasSuffix(d.Name(), "_test.rego") {
				return nil
			}
			src, readErr := policiesFS.ReadFile(p)
			if readErr != nil {
				return fmt.Errorf("read %s: %w", p, readErr)
			}
			bundle.Modules = append(bundle.Modules, Module{Path: p, Source: string(src)})
		case ".json":
			if d.Name() != "metadata.json" {
				return nil
			}
			raw, readErr := policiesFS.ReadFile(p)
			if readErr != nil {
				return fmt.Errorf("read %s: %w", p, readErr)
			}
			var meta Metadata
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.DisallowUnknownFields()
			if decErr := decoder.Decode(&meta); decErr != nil {
				return fmt.Errorf("parse %s: %w", p, decErr)
			}
			check := Check{Metadata: meta, Dir: path.Dir(p)}
			if valErr := check.validate(); valErr != nil {
				return fmt.Errorf("%s: %w", p, valErr)
			}
			if prev, dup := seen[meta.ID]; dup {
				return fmt.Errorf("%s: duplicate check ID %s (also in %s)", p, meta.ID, prev)
			}
			seen[meta.ID] = p
			bundle.Checks = append(bundle.Checks, check)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(bundle.Checks, func(i, j int) bool {
		a, b := bundle.Checks[i], bundle.Checks[j]
		// Controls without a benchmark number sort after those with one: they
		// are supplements to the mapping, not part of it, and a reader scanning
		// the list in benchmark order should meet the benchmark first. Among
		// themselves they order by ID so the listing stays deterministic.
		switch {
		case a.CISID == "" && b.CISID == "":
			return a.ID < b.ID
		case a.CISID == "":
			return false
		case b.CISID == "":
			return true
		}
		return LessCISID(a.CISID, b.CISID)
	})
	sort.Slice(bundle.Modules, func(i, j int) bool {
		return bundle.Modules[i].Path < bundle.Modules[j].Path
	})
	return bundle, nil
}

func (c Check) validate() error {
	if c.ID == "" {
		return fmt.Errorf("id is required")
	}
	if c.Package == "" {
		return fmt.Errorf("package is required")
	}
	switch c.Scope {
	case ScopeController, ScopeJob:
	default:
		return fmt.Errorf("scope %q must be %q or %q", c.Scope, ScopeController, ScopeJob)
	}
	switch strings.ToUpper(c.Severity) {
	case SeverityHigh, SeverityMedium, SeverityLow:
	default:
		return fmt.Errorf("severity %q must be HIGH, MEDIUM or LOW", c.Severity)
	}
	if c.Title == "" {
		return fmt.Errorf("title is required")
	}
	if c.Remediation == "" {
		return fmt.Errorf("remediation is required")
	}
	if c.FixSummary == "" {
		return fmt.Errorf("fixSummary is required")
	}
	if len(c.Platforms) == 0 {
		return fmt.Errorf("at least one platform is required")
	}
	return nil
}

// AppliesTo reports whether the check covers the given platform.
func (c Check) AppliesTo(platform string) bool {
	for _, p := range c.Platforms {
		if strings.EqualFold(p, platform) {
			return true
		}
	}
	return false
}

// LessCISID orders identifiers like "1.1.9" before "1.1.11" by comparing each
// dotted component numerically instead of lexically. Every place that presents
// controls in benchmark order must use this: a plain string comparison sorts
// "1.1.15" ahead of "1.1.3", which is the order nobody reading a benchmark
// expects.
func LessCISID(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, errA := atoi(as[i])
		y, errB := atoi(bs[i])
		if errA != nil || errB != nil {
			if as[i] != bs[i] {
				return as[i] < bs[i]
			}
			continue
		}
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}

func atoi(s string) (int, error) {
	var n int
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// Package config holds the tunable thresholds that policies read. Every value
// here is handed to Rego as `input.config`, so a rule never hard-codes a number
// that a user might reasonably disagree with.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full evaluation configuration.
type Config struct {
	// Scan holds the settings that describe the deployment rather than any
	// one run: how to reach the instance, how hard to drive it, and what its
	// exit thresholds are. They used to be nine scan flags, which made every
	// invocation restate facts about the instance that never change between
	// runs. Excluded from the policy input (json:"-"): no rule reads them,
	// and keeping them out leaves input.config byte-identical.
	Scan Scan `yaml:"scan" json:"-"`
	// Thresholds are the numeric knobs used by the policies.
	Thresholds Thresholds `yaml:"thresholds" json:"thresholds"`
	// SkipDisabledJobs drops disabled jobs from the scan entirely, rather than
	// reporting NA for each of them. Off by default: a disabled job is still
	// configuration somebody can re-enable, and a report that silently omits
	// them describes a smaller controller than the one that exists.
	SkipDisabledJobs bool `yaml:"skipDisabledJobs" json:"skipDisabledJobs"`
	// Exclude lists check IDs (e.g. "CIS-2.1.6") to leave out of the run.
	Exclude []string `yaml:"exclude" json:"exclude"`
	// Include, when non-empty, restricts the run to these check IDs.
	Include []string `yaml:"include" json:"include"`
}

// Scan is the deployment-stable half of a scan's configuration.
type Scan struct {
	// FailOn exits 1 when a failure at or above this severity exists:
	// high, medium, low, or none.
	FailOn string `yaml:"failOn"`
	// FailUnder exits 1 when the score is below it; 0 disables.
	FailUnder int `yaml:"failUnder"`
	// MaxManual exits 1 when more than this percent of controls need manual
	// review; -1 disables. It defaults to off because how much of an
	// instance a token can read is a property of the deployment, and a guess
	// here would fail scans that are working as well as they can.
	MaxManual int `yaml:"maxManual"`
	// Concurrency is how many repositories to fetch in parallel.
	Concurrency int `yaml:"concurrency"`
	// Timeout bounds a single HTTP request, e.g. "30s".
	Timeout Duration `yaml:"timeout"`
	// MaxDuration abandons the scan after this long; 0 means no limit.
	MaxDuration Duration `yaml:"maxDuration"`
	// Insecure skips TLS certificate verification, for private CAs.
	Insecure bool `yaml:"insecure"`
	// AllowPlaintext permits an http:// URL, sending credentials in the
	// clear.
	AllowPlaintext bool `yaml:"allowPlaintext"`
	// Progress is what to show while scanning: full, compact, or off.
	Progress string `yaml:"progress"`
	// Cache keeps each network scan's snapshot (0600, under the user config
	// directory) so `scan --last` can re-render it — --details, another
	// format, new thresholds — without contacting the instance again. The
	// snapshot is a map of the instance's weak points, which is why this is
	// a config key at all: false keeps it off disk.
	Cache bool `yaml:"cache"`
}

// Duration is time.Duration that reads YAML the way people write durations:
// "30s", "2m", "1h30m". A bare number would be nanoseconds, which nobody
// means, so it is rejected with the spelling that works.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("a duration is a string like \"30s\" or \"5m\", got %s", value.Value)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Get() time.Duration { return time.Duration(d) }

// Thresholds are the numeric policy knobs.
type Thresholds struct {
	// UpdateSiteMaxAgeDays is how stale the controller's cached update-centre
	// data may be before a control about plugin currency stops trusting it.
	//
	// It exists because hasUpdate is computed against that cache. A controller
	// that has never reached updates.jenkins.io — air-gapped, or behind a proxy
	// that never worked — reports hasUpdate false for every plugin, and a
	// control reading it would report PASS on an instance that has no idea
	// whether it is out of date. Past this age the answer is MANUAL.
	UpdateSiteMaxAgeDays int `yaml:"updateSiteMaxAgeDays" json:"updateSiteMaxAgeDays"`
}

// Default returns the configuration used when the user supplies none. The
// values follow the CIS Software Supply Chain Security Guide where it is
// specific, and common practice where it is not.
func Default() Config {
	return Config{
		Scan: Scan{
			FailOn:      "high",
			FailUnder:   0,
			MaxManual:   -1,
			Concurrency: 8,
			Timeout:     Duration(30 * time.Second),
			MaxDuration: 0,
			Progress:    "compact",
			Cache:       true,
		},
		Thresholds: Thresholds{
			UpdateSiteMaxAgeDays: 30,
		},
	}
}

// Load reads a YAML config from path and overlays it on the defaults, so a
// user file only needs to mention what it changes.
func Load(path string) (Config, error) {
	return LoadWithOverrides(path, nil)
}

// LoadWithOverrides is Load plus per-run overrides: each set entry is a
// "key=value" naming a config key by its dotted YAML path, applied over
// whatever the file said. Validation runs once, at the end, so an override
// is checked exactly as hard as the file it overrides.
func LoadWithOverrides(path string, sets []string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		// Decoding onto the populated struct leaves absent keys at their default.
		// Sequences are the exception: YAML replaces them wholesale, which is what
		// a user who lists signature hook keys expects.
		//
		// KnownFields is on because the failure mode without it is silent and
		// wrong: `minApprover` for `minApprovers` parses cleanly, changes nothing,
		// and produces a report the user believes was evaluated at their threshold.
		// An audit tool that quietly ignores its own configuration is worse than
		// one that refuses to start.
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			// An empty file is not an error: it means "keep every default".
			if !errors.Is(err, io.EOF) {
				return cfg, fmt.Errorf("parse config %s: %w", path, err)
			}
		}
	}
	for _, set := range sets {
		if err := applyOverride(&cfg, set); err != nil {
			return cfg, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// keySegment is what a piece of a dotted config key may look like. Anything
// else is refused before it can reach the YAML text an override is turned
// into.
var keySegment = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// applyOverride applies one "key=value" onto the config.
//
// It works by writing the override as the YAML document it is shorthand for —
// scan.failOn=none becomes "scan:\n  failOn: none\n" — and decoding that onto
// the config with the same strict decoder the file gets. Everything then
// comes for free and cannot drift from the file's behaviour: the value
// parsing (ints, bools, "30s" durations, [flow, sequences]), the overlay
// semantics, and the refusal of unknown keys.
func applyOverride(cfg *Config, set string) error {
	key, value, ok := strings.Cut(set, "=")
	if !ok {
		return fmt.Errorf("--set %q is not key=value; e.g. --set scan.failOn=none", set)
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("--set %q: the value must be a single line", set)
	}
	segments := strings.Split(key, ".")
	var doc strings.Builder
	for i, seg := range segments {
		if !keySegment.MatchString(seg) {
			return fmt.Errorf("--set %q: %q is not a config key", set, key)
		}
		indent := strings.Repeat("  ", i)
		if i < len(segments)-1 {
			fmt.Fprintf(&doc, "%s%s:\n", indent, seg)
		} else {
			fmt.Fprintf(&doc, "%s%s: %s\n", indent, seg, value)
		}
	}

	decoder := yaml.NewDecoder(strings.NewReader(doc.String()))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("--set %q: %w", set, err)
	}
	return nil
}

// Validate rejects thresholds that would make a policy meaningless.
func (c Config) Validate() error {
	// The scan section first. These were flag validations once; the checks
	// move with the settings.
	s := c.Scan
	switch strings.ToLower(s.FailOn) {
	case "high", "medium", "low", "none":
	default:
		return fmt.Errorf("scan.failOn %q: want high, medium, low or none", s.FailOn)
	}
	switch strings.ToLower(s.Progress) {
	case "full", "compact", "off":
	default:
		return fmt.Errorf("scan.progress %q: want full, compact or off", s.Progress)
	}
	if s.Concurrency < 1 {
		return fmt.Errorf("scan.concurrency must be at least 1, got %d", s.Concurrency)
	}
	if s.FailUnder < 0 || s.FailUnder > 100 {
		return fmt.Errorf("scan.failUnder must be between 0 and 100, got %d", s.FailUnder)
	}
	if s.MaxManual < -1 || s.MaxManual > 100 {
		return fmt.Errorf("scan.maxManual must be between 0 and 100, or -1 to disable, got %d", s.MaxManual)
	}
	if s.Timeout.Get() < 0 || s.MaxDuration.Get() < 0 {
		return fmt.Errorf("scan.timeout and scan.maxDuration must not be negative")
	}

	// Every threshold is checked, not just the ones that looked risky.
	//
	// A negative threshold does not merely produce an odd number: it silently
	// inverts the control it feeds. `updateSiteMaxAgeDays: -1` makes every
	// controller's cached update-centre data older than the limit, so the
	// plugin currency control reports MANUAL everywhere and quietly stops
	// being a control at all — with nothing in the report to say why. A single
	// typo reconfigures a check into something that is not a check any more,
	// which is why this is a startup error rather than a warning.
	t := c.Thresholds
	for _, f := range []struct {
		name  string
		value int
	}{
		{"updateSiteMaxAgeDays", t.UpdateSiteMaxAgeDays},
	} {
		if f.value < 0 {
			return fmt.Errorf("thresholds.%s must be >= 0, got %d", f.name, f.value)
		}
	}

	// A blank entry in either list is a typo that silently changes the run: an
	// empty string in `include` selects nothing rather than everything, and one
	// in `exclude` is a line somebody meant to fill in. Neither produces an
	// error later — the scan just covers a different set of controls than the
	// file says it does.
	for _, list := range []struct {
		field string
		items []string
	}{
		{"exclude", c.Exclude},
		{"include", c.Include},
	} {
		for i, item := range list.items {
			if strings.TrimSpace(item) == "" {
				return fmt.Errorf("%s[%d] is empty; remove the entry rather than leaving it blank", list.field, i)
			}
		}
	}
	return nil
}

// Selects reports whether a check ID should run under this configuration.
func (c Config) Selects(id string) bool {
	for _, ex := range c.Exclude {
		if strings.EqualFold(strings.TrimSpace(ex), id) {
			return false
		}
	}
	if len(c.Include) == 0 {
		return true
	}
	for _, in := range c.Include {
		if strings.EqualFold(strings.TrimSpace(in), id) {
			return true
		}
	}
	return false
}

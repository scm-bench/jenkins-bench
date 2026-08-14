package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/scm-bench/jenkins-bench/internal/checks"
	"github.com/scm-bench/jenkins-bench/internal/console"
	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// controlTally is one row of the Findings overview: a control and how it came
// out across every resource it applies to.
type controlTally struct {
	checkID  string
	cisID    string
	title    string
	severity string
	// status is the row's kind: statusFail, statusManual or statusPass. A
	// control lands in exactly one of them — FAIL if it failed anywhere,
	// MANUAL if it is documented as unanswerable, PASS otherwise.
	status string
	// affected counts the resources in this row's state; applicable counts
	// the resources the control was evaluated against at all (NA excluded,
	// unread included — an unread instance is one the verdict does not cover,
	// and the fraction should say so).
	affected   int
	applicable int
	// affectedNames are the resources behind affected, in report order, so a
	// partial row can say which ones instead of leaving the reader to guess
	// from a fraction.
	affectedNames []string
	// instance marks a control evaluated against the instance itself; its
	// row says so instead of showing a 1/1 that names no job.
	instance bool
}

// tallyControls aggregates findings by control for the overview table.
//
// UNREAD findings (unread(f)) never produce a row of their own: they are one
// cause — the scan could not read something — already explained once in the
// scan warnings, and a row per control per resource is how the old layout made
// thirteen of them read as twenty-six. They only widen the denominators here
// and feed the one-sentence summary below the table.
func tallyControls(findings []engine.Finding, showPassed bool) []controlTally {
	index := map[string]int{}
	var out []controlTally
	for _, f := range findings {
		if f.Status == engine.StatusNA {
			continue
		}
		i, ok := index[f.CheckID]
		if !ok {
			i = len(out)
			index[f.CheckID] = i
			out = append(out, controlTally{
				checkID:  f.CheckID,
				cisID:    f.CISID,
				title:    f.Title,
				severity: strings.ToUpper(f.Severity),
			})
		}
		out[i].applicable++
		if f.Resource == engine.InstanceResourceName {
			out[i].instance = true
		}
		switch {
		case f.Status == engine.StatusFail:
			if out[i].status != statusFail {
				out[i].status = statusFail
				out[i].affected = 0
				out[i].affectedNames = nil
			}
			out[i].affected++
			out[i].affectedNames = append(out[i].affectedNames, f.Resource)
		case unread(f):
			// Denominator only.
		case f.Status == engine.StatusManual:
			if out[i].status == "" || out[i].status == statusPass {
				out[i].status = statusManual
				out[i].affected = 0
				out[i].affectedNames = nil
			}
			if out[i].status == statusManual {
				out[i].affected++
				out[i].affectedNames = append(out[i].affectedNames, f.Resource)
			}
		case f.Status == engine.StatusPass:
			if out[i].status == "" {
				out[i].status = statusPass
			}
			if out[i].status == statusPass {
				out[i].affected++
			}
		}
	}

	kept := out[:0]
	for _, t := range out {
		switch t.status {
		case statusFail, statusManual:
			kept = append(kept, t)
		case statusPass:
			if showPassed {
				kept = append(kept, t)
			}
		}
		// status "" means every instance went unread; the sentence covers it.
	}
	out = kept

	rank := map[string]int{statusFail: 0, statusManual: 1, statusPass: 2}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if rank[x.status] != rank[y.status] {
			return rank[x.status] < rank[y.status]
		}
		if wa, wb := checks.Weight(x.severity), checks.Weight(y.severity); wa != wb {
			return wa > wb
		}
		return checks.LessCISID(x.cisID, y.cisID)
	})
	return out
}

// writeFindingsOverview is the body of the default report: one row per
// control, aggregated across every resource it was evaluated against.
//
// This is the other side of the trade writeTable's per-resource sections make.
// A control that fails identically across fifty jobs is one
// misconfiguration, and here it reads as one row saying 50/50; the per-resource
// layout that answers "what is wrong with *my* job" is a --details
// away.
func writeFindingsOverview(w io.Writer, rep *engine.Report, p painter, width int, opts Options) {
	tallies := tallyControls(rep.Findings, opts.ShowPassed)

	blank(w)
	line(w, "%s", p.paint(ansiBold, "Findings"))
	blank(w)

	if len(tallies) == 0 {
		line(w, "%s", p.paint(ansiDim, "No failed or manual-review controls."))
	} else {
		cols := []console.Column{
			{Header: "Control", Align: console.AlignLeft,
				Colour: func(s string) string { return p.paint(ansiCyan, s) }},
			{Header: "Severity", Align: console.AlignLeft, Colour: severityColour(p)},
			{Header: "Status", Align: console.AlignLeft, Colour: statusColour(p)},
			{Header: "Resources", Align: console.AlignRight},
			{Header: "Title", Align: console.AlignLeft, Flex: true},
		}
		rows := make([][]string, 0, len(tallies))
		for _, t := range tallies {
			rows = append(rows, []string{
				t.checkID,
				t.severity,
				t.status,
				resourcesCell(t),
				titleCell(t),
			})
		}
		console.RenderTable(w, width, cols, rows)
		for _, l := range console.Wrap("Resources: how many are in this state / how many the control was evaluated against; 'controller' is the Jenkins controller itself.", width) {
			line(w, "%s", p.paint(ansiDim, l))
		}
	}

	if sentence := unreadSummary(rep.Findings); sentence != "" {
		if len(rep.Metadata.Warnings) > 0 {
			sentence += "; see Scan warnings below."
		} else {
			sentence += "."
		}
		blank(w)
		for _, l := range console.Wrap(sentence, width) {
			line(w, "%s", p.paint(ansiYellow, l))
		}
	}
}

// resourcesCell is the row's spread. A controller-level control says so by
// name: its 1/1 named no job, which is exactly the kind of row a reader tries
// and fails to match to one. The word matches engine.InstanceResourceName and
// the legend, which it did not when this domain renamed the instance scope.
func resourcesCell(t controlTally) string {
	if t.instance {
		return engine.InstanceResourceName
	}
	return fmt.Sprintf("%d/%d", t.affected, t.applicable)
}

// maxNamedResources caps how many resources a partial row names before
// summarising the rest; past a handful the list stops being read and starts
// being skipped.
const maxNamedResources = 4

// titleCell is the control's title, and — when the control caught only some
// of its resources — a second line naming which ones, in the Finding column's
// "· " idiom. A full sweep needs no list: the fraction already says all.
func titleCell(t controlTally) string {
	if t.instance || t.affected == 0 || t.affected >= t.applicable {
		return t.title
	}
	var label string
	switch t.status {
	case statusFail:
		label = "failing"
	case statusManual:
		label = "needs review"
	default:
		return t.title
	}
	names := shortNames(t.affectedNames)
	if extra := len(names) - maxNamedResources; extra > 0 {
		names = append(names[:maxNamedResources], fmt.Sprintf("+%d more", extra))
	}
	return t.title + "\n· " + label + ": " + strings.Join(names, ", ")
}

// shortNames drops the project prefix when every name shares it — inside one
// project the prefix is pure repetition — and leaves full names alone the
// moment two projects mix.
func shortNames(names []string) []string {
	prefix := ""
	for i, n := range names {
		key, _, ok := strings.Cut(n, "/")
		if !ok {
			return names
		}
		if i == 0 {
			prefix = key
			continue
		}
		if key != prefix {
			return names
		}
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimPrefix(n, prefix+"/")
	}
	return out
}

// unreadSummary folds every unread finding into one clause, or "" when
// nothing went unread. The cause — a 401, a missing permission — is already a
// scan warning, so the caller points there instead of repeating it per
// control per resource.
func unreadSummary(findings []engine.Finding) string {
	controls := map[string]bool{}
	resources := map[string]bool{}
	var one string
	for _, f := range findings {
		if !unread(f) {
			continue
		}
		controls[f.CheckID] = true
		resources[f.Resource] = true
		one = f.Resource
	}
	if len(controls) == 0 {
		return ""
	}
	where := "on " + one
	if len(resources) > 1 {
		where = fmt.Sprintf("across %s", console.Pluralize(len(resources), "resource"))
	}
	return fmt.Sprintf("%s could not be read (Unread) %s",
		console.Pluralize(len(controls), "control"), where)
}

// writeHint closes the overview with where the rest of the report lives. It is
// the discoverability mechanism for --details, so it always prints in overview
// mode — including under --demo, which is where new users meet the tool.
func writeHint(w io.Writer, p painter, width int) {
	blank(w)
	text := "Details: rerun with --details for per-resource findings and full remediation steps, " +
		"or --details=<resource|control>[,...] to filter; -o json for the full report."
	for _, l := range console.Wrap(text, width) {
		line(w, "%s", p.paint(ansiDim, l))
	}
}

// detailFilter is the parsed form of --details: which controls and which
// resources the per-resource sections should cover. Empty means everything.
type detailFilter struct {
	controls  map[string]bool // canonical CheckIDs, matched exactly
	resources []string        // lowercased substrings of resource names
}

func (f detailFilter) empty() bool { return len(f.controls) == 0 && len(f.resources) == 0 }

// parseDetailFilters classifies each --details value against the report.
//
// A value is a control filter when, case-insensitively and with an optional
// CIS- prefix supplied, it exactly equals a CheckID in the report — exact,
// because a substring match on dotted numbers would make "1.1" silently mean
// nine controls. Anything else is a resource filter, matched as a
// case-insensitive substring of the resource name. A value matching neither is
// an error rather than a warning: a filter that matched nothing would render a
// report indistinguishable from a clean one.
//
// "all" is the sentinel a bare --details produces and matches everything.
func parseDetailFilters(values []string, findings []engine.Finding) (detailFilter, error) {
	ids := map[string]string{}
	for _, f := range findings {
		ids[strings.ToLower(f.CheckID)] = f.CheckID
	}

	out := detailFilter{controls: map[string]bool{}}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || strings.EqualFold(v, "all") {
			continue
		}
		lower := strings.ToLower(v)
		if id, ok := ids[lower]; ok {
			out.controls[id] = true
			continue
		}
		if id, ok := ids["cis-"+lower]; ok {
			out.controls[id] = true
			continue
		}
		matched := false
		for _, f := range findings {
			if strings.Contains(strings.ToLower(f.Resource), lower) {
				matched = true
				break
			}
		}
		if !matched {
			return detailFilter{}, fmt.Errorf(
				"--details %q matched no control ID and no resource in this report; resources are listed in Report Summary, controls in list-checks", v)
		}
		out.resources = append(out.resources, lower)
	}
	return out, nil
}

// filterFindings keeps the findings the filter selects: resources matching any
// resource value (all, when none were given) AND controls matching any control
// value (likewise).
func filterFindings(findings []engine.Finding, filter detailFilter) []engine.Finding {
	if filter.empty() {
		return findings
	}
	var out []engine.Finding
	for _, f := range findings {
		if len(filter.controls) > 0 && !filter.controls[f.CheckID] {
			continue
		}
		if len(filter.resources) > 0 {
			lower := strings.ToLower(f.Resource)
			hit := false
			for _, sub := range filter.resources {
				if strings.Contains(lower, sub) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

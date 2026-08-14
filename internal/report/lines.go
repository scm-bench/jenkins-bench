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

// The default report body: one finding per record, the shape linters use.
//
// A failure is read in one place — which resource, which control, why, and the
// fix — instead of being split across a summary matrix, an aggregate table and
// a remediation section three screens apart. Column 0 is the record delimiter:
// a finding starts flush-left and every continuation is indented, so the eye
// and grep both parse it.

// contIndent is the continuation indent for wrapped record text.
const contIndent = "    "

// minFlowWidth is the narrowest column Details will share a line with its
// prefix; below it the text starts on its own line instead of squeezing.
const minFlowWidth = 20

// writeFindingLines renders the findings: FAIL records, PASS records (with
// ShowPassed), aggregated MANUAL groups, aggregated N/A groups (with
// ShowPassed), then the one-sentence unread summary. Unread findings are not
// listed per record — they are one cause, explained once in the scan warnings.
func writeFindingLines(w io.Writer, rep *engine.Report, p painter, width int, opts Options) {
	var fails, passes []engine.Finding
	for _, f := range rep.Findings {
		switch {
		case f.Status == engine.StatusFail:
			fails = append(fails, f)
		case f.Status == engine.StatusPass && opts.ShowPassed:
			passes = append(passes, f)
		}
	}
	manuals := groupByControlDetails(rep.Findings, func(f engine.Finding) bool {
		return f.Status == engine.StatusManual && !unread(f)
	})
	var nas []findingGroup
	if opts.ShowPassed {
		nas = groupByControlDetails(rep.Findings, func(f engine.Finding) bool {
			return f.Status == engine.StatusNA
		})
	}
	unreadSentence := unreadSummary(rep.Findings)

	if len(fails) == 0 && len(passes) == 0 && len(manuals) == 0 && len(nas) == 0 && unreadSentence == "" {
		blank(w)
		line(w, "%s", p.paint(ansiGreen, "No failed or manual-review controls."))
		return
	}

	if len(fails) > 0 {
		blank(w)
		for _, f := range controllerFirst(fails) {
			writeFindingLine(w, p, width, f, opts)
		}
	}
	if len(passes) > 0 {
		blank(w)
		for _, f := range controllerFirst(passes) {
			writeFindingLine(w, p, width, f, opts)
		}
	}
	if len(manuals) > 0 {
		blank(w)
		writeGroupLines(w, p, width, statusManual, manuals, opts)
	}
	if len(nas) > 0 {
		blank(w)
		writeGroupLines(w, p, width, statusNA, nas, opts)
	}

	if unreadSentence != "" {
		if len(rep.Metadata.Warnings) > 0 {
			unreadSentence += "; see Scan warnings below."
		} else {
			unreadSentence += "."
		}
		blank(w)
		for _, l := range console.Wrap(unreadSentence, width) {
			line(w, "%s", p.paint(ansiYellow, l))
		}
	}
}

// writeFindingLine renders one record:
//
//	<resource>  <CHECK-ID> <SEVERITY>: <details>
//	    fix: <one-line remediation>
//	    · <evidence>
func writeFindingLine(w io.Writer, p painter, width int, f engine.Finding, opts Options) {
	sev := strings.ToUpper(f.Severity)
	label, labelColour := sev, severityColour(p)
	if f.Status == engine.StatusPass {
		label, labelColour = statusPass, statusColour(p)
	}
	head := fmt.Sprintf("%s  %s %s: ",
		p.paint(ansiBold, f.Resource),
		p.paint(ansiCyan, f.CheckID),
		labelColour(label))
	headWidth := len(f.Resource) + 2 + len(f.CheckID) + 1 + len(label) + 2
	flowLine(w, width, head, headWidth, f.Details)

	if f.Status != engine.StatusFail {
		return
	}
	if !opts.NoRemediations {
		fixHead := contIndent + p.paint(ansiBold, "fix:") + " "
		flowLine(w, width, fixHead, len(contIndent)+5, fixLine(f))
	}
	for _, e := range f.Evidence {
		for i, l := range console.Wrap(e, width-len(contIndent)-2) {
			if i == 0 {
				line(w, "%s%s", contIndent, p.paint(ansiDim, "· "+l))
				continue
			}
			line(w, "%s  %s", contIndent, p.paint(ansiDim, l))
		}
	}
}

// flowLine writes head followed by text, wrapping the text and indenting every
// continuation by contIndent. head is already painted; headWidth is its width
// without paint. When the head leaves too little room, the text starts on the
// next line instead of squeezing into a sliver — the head may then overflow the
// width on its own, the same unbreakable-token policy the header applies to a
// long base URL.
func flowLine(w io.Writer, width int, head string, headWidth int, text string) {
	if width-headWidth < minFlowWidth {
		line(w, "%s", strings.TrimRight(head, " "))
		for _, l := range console.Wrap(text, width-len(contIndent)) {
			line(w, "%s%s", contIndent, l)
		}
		return
	}
	// Two widths, not one: the first line shares the row with the head, the
	// continuations get almost the whole terminal back. Wrapping everything at
	// the first line's width squeezed every continuation into the head-sized
	// column it no longer shares the row with.
	first := console.Wrap(text, width-headWidth)
	line(w, "%s%s", head, first[0])
	if rest := strings.Join(first[1:], " "); rest != "" {
		for _, l := range console.Wrap(rest, width-len(contIndent)) {
			line(w, "%s%s", contIndent, l)
		}
	}
}

// findingGroup is one aggregated line: a control, the shared reason, and the
// resources it covers.
type findingGroup struct {
	rep       engine.Finding // representative: severity, fix, IDs
	details   string
	resources []string
	instance  bool
	kinds     map[string]bool
}

// groupByControlDetails folds findings into one group per (CheckID, Details).
//
// The pair, not the CheckID alone: two resources can be MANUAL for different
// reasons, and collapsing them under whichever reason came first would be a
// small lie. In practice the Details of a MANUAL control are constant across
// resources, so a control almost always folds to a single line.
func groupByControlDetails(findings []engine.Finding, keep func(engine.Finding) bool) []findingGroup {
	index := map[string]int{}
	var out []findingGroup
	for _, f := range findings {
		if !keep(f) {
			continue
		}
		key := f.CheckID + "\x00" + f.Details
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, findingGroup{rep: f, details: f.Details, kinds: map[string]bool{}})
		}
		out[i].resources = append(out[i].resources, f.Resource)
		out[i].kinds[f.ResourceType] = true
		if f.Resource == engine.InstanceResourceName {
			out[i].instance = true
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if wa, wb := checks.Weight(x.rep.Severity), checks.Weight(y.rep.Severity); wa != wb {
			return wa > wb
		}
		if x.rep.CISID != y.rep.CISID {
			return checks.LessCISID(x.rep.CISID, y.rep.CISID)
		}
		if len(x.resources) != len(y.resources) {
			return len(x.resources) > len(y.resources)
		}
		return x.details < y.details
	})
	return out
}

// countLabel names what a group spans: the instance by name, anything else by
// count and resource kind.
func (g findingGroup) countLabel() string {
	if g.instance && len(g.resources) == 1 {
		return engine.InstanceResourceName
	}
	noun := "resource"
	if len(g.kinds) == 1 {
		for k := range g.kinds {
			if k != "" {
				noun = strings.ToLower(k)
			}
		}
	}
	return console.Pluralize(len(g.resources), noun)
}

// writeGroupLines renders aggregated records:
//
//	<CHECK-ID> <STATUS> (<count>): <details>
//	    fix: <one-line remediation>
//
// One question needing a person is one question however many resources it
// spans; the per-resource split is a --details away.
func writeGroupLines(w io.Writer, p painter, width int, status string, groups []findingGroup, opts Options) {
	for _, g := range groups {
		count := g.countLabel()
		head := fmt.Sprintf("%s %s (%s): ",
			p.paint(ansiCyan, g.rep.CheckID),
			statusColour(p)(status),
			count)
		headWidth := len(g.rep.CheckID) + 1 + len(status) + 2 + len(count) + 3
		flowLine(w, width, head, headWidth, g.details)

		if status == statusManual && !opts.NoRemediations {
			fixHead := contIndent + p.paint(ansiBold, "fix:") + " "
			flowLine(w, width, fixHead, len(contIndent)+5, fixLine(g.rep))
		}
	}
}

// controllerFirst orders findings so the instance's records lead within each
// control; everything else keeps the engine's order (severity, benchmark
// number, resource).
func controllerFirst(findings []engine.Finding) []engine.Finding {
	out := make([]engine.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if x.CheckID == y.CheckID {
			return x.Resource == engine.InstanceResourceName && y.Resource != engine.InstanceResourceName
		}
		return false
	})
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

// writeHint closes the report body with where the rest lives. It is the
// discoverability mechanism for --details, so it always prints in the default
// layout.
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
				"--details %q matched no control ID and no resource in this report; resource names appear in the scan output, controls in list-checks", v)
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

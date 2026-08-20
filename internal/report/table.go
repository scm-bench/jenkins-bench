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

// ANSI codes come from internal/console so the report and the scan trace cannot
// drift apart. The local names are kept because they read better at the call
// sites here, where nearly every line paints something.
const (
	ansiReset  = console.Reset
	ansiBold   = console.Bold
	ansiDim    = console.Dim
	ansiRed    = console.Red
	ansiGreen  = console.Green
	ansiYellow = console.Yellow
	ansiCyan   = console.Cyan
)

type painter struct{ enabled bool }

func (p painter) paint(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return code + s + ansiReset
}

// writeTable renders the report in one of two layouts.
//
// The default is line-oriented, the shape linters use: one record per failure
// carrying the resource, the control, the reason and the fix together, MANUAL
// aggregated to a line per control, and the score block last — the verdict is
// the final thing printed, and every number above it is checkable. Findings
// the scan could not read collapse to a single sentence pointing at the scan
// warnings that explain them.
//
// Options.Details flips to the per-resource layout, trivy's shape: one
// section per resource, each a table of what that resource got wrong, with the
// full remediation paragraphs at the end. That answers the other question a
// reader arrives with — "what is wrong with *my* job" — and
// Options.DetailFilters narrows it to the resources or controls named.
func writeTable(w io.Writer, rep *engine.Report, opts Options) error {
	p := painter{enabled: opts.Color}
	width := opts.Width
	if width == 0 {
		width = console.Width()
	}

	if opts.Details {
		// Parsed before anything is written, so a filter that matches nothing
		// is an error and not a report that looks clean.
		filter, err := parseDetailFilters(opts.DetailFilters, rep.Findings)
		if err != nil {
			return err
		}
		filtered := filterFindings(rep.Findings, filter)

		writeHeader(w, rep, p, width)
		writeNotice(w, p, width, opts.Notice)
		writeWarnings(w, rep, p, width, !opts.NoRemediations)
		writeResourceSections(w, filtered, p, width, opts)
		if !opts.NoRemediations {
			writeRemediations(w, filtered, p, width)
		}
		writeSummary(w, rep, p, width)
		return nil
	}

	writeHeader(w, rep, p, width)
	writeNotice(w, p, width, opts.Notice)
	writeFindingLines(w, rep, p, width, opts)
	// After the findings rather than before them: the unread sentence points
	// here, and the cause should sit next to the symptom.
	writeWarnings(w, rep, p, width, !opts.NoRemediations)
	if !opts.NoRemediations {
		writeRulesIndex(w, rep, p, width)
	}
	writeHint(w, p, width)
	writeSummary(w, rep, p, width)
	return nil
}

func line(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format+"\n", args...)
}

func blank(w io.Writer) { fmt.Fprintln(w) }

// prose writes wrapped text with a hanging indent, for the parts of the report
// that are paragraphs rather than table cells.
func prose(w io.Writer, width int, prefix string, prefixWidth int, text string) {
	lines := console.Wrap(text, width-prefixWidth)
	pad := strings.Repeat(" ", prefixWidth)
	for i, l := range lines {
		if i == 0 {
			line(w, "%s%s", prefix, l)
			continue
		}
		line(w, "%s%s", pad, l)
	}
}

// writeHeader names what was scanned and when.
//
// It splits rather than wraps. The parts are separated by a padded "·" that
// wrapping would collapse to a single space, and breaking between two of them
// mid separator reads as damage, so instead the line sheds a part at a time:
// first the timestamp, then the URL. A base URL longer than the terminal is
// still longer than the terminal — it is one unbreakable token, and cutting it
// would produce something nobody can paste back.
func writeHeader(w io.Writer, rep *engine.Report, p painter, width int) {
	m := rep.Metadata
	stamp := m.GeneratedAt.Format("2006-01-02 15:04:05 MST")
	name := p.paint(ansiBold, "jenkins-bench")

	if fits(width, "jenkins-bench %s  ·  %s  ·  %s", m.ToolVersion, m.BaseURL, stamp) {
		line(w, "%s %s  ·  %s  ·  %s", name, m.ToolVersion, m.BaseURL, stamp)
		return
	}
	if fits(width, "jenkins-bench %s  ·  %s", m.ToolVersion, m.BaseURL) {
		line(w, "%s %s  ·  %s", name, m.ToolVersion, m.BaseURL)
		line(w, "%s", p.paint(ansiDim, "scanned "+stamp))
		return
	}
	line(w, "%s %s", name, m.ToolVersion)
	line(w, "%s", m.BaseURL)
	line(w, "%s", p.paint(ansiDim, "scanned "+stamp))
}

// writeNotice renders Options.Notice directly under the header, bold and
// yellow: the one thing a reader must take in before believing anything the
// tables below say. Yellow because the tag vocabulary already uses it for
// "needs a person's judgement", which is exactly what a caveat is.
func writeNotice(w io.Writer, p painter, width int, text string) {
	if text == "" {
		return
	}
	blank(w)
	for _, l := range console.Wrap(text, width) {
		line(w, "%s", p.paint(ansiBold+ansiYellow, l))
	}
}

// fits reports whether the uncoloured form of a line stays inside the width.
func fits(width int, format string, args ...any) bool {
	return len([]rune(fmt.Sprintf(format, args...))) <= width
}

// writeSummary opens with the score and the counts behind it.
//
// Every line below the score states its own arithmetic, so the numbers are
// checkable rather than something to trust. The state names are PASS, FAIL,
// MANUAL and NA — the ones in the JSON and in `list-checks`.
func writeSummary(w io.Writer, rep *engine.Report, p painter, width int) {
	s := rep.Score

	scoreColor := ansiGreen
	switch {
	case s.Value < 50:
		scoreColor = ansiRed
	case s.Value < 80:
		scoreColor = ansiYellow
	}
	blank(w)

	score := fmt.Sprintf("SCORE %d/100", s.Value)
	counts := fmt.Sprintf("%d passed  %d failed  %d manual  %d n/a",
		s.Passed, s.Failed, s.Manual, s.NotApplicable)
	painted := fmt.Sprintf("%s  %s  %s  %s",
		p.paint(ansiGreen, fmt.Sprintf("%d passed", s.Passed)),
		p.paint(ansiRed, fmt.Sprintf("%d failed", s.Failed)),
		p.paint(ansiYellow, fmt.Sprintf("%d manual", s.Manual)),
		p.paint(ansiDim, fmt.Sprintf("%d n/a", s.NotApplicable)),
	)
	head := p.paint(ansiBold, "SCORE") + " " + p.paint(scoreColor+ansiBold, fmt.Sprintf("%d/100", s.Value))
	// Measured on the uncoloured text: the escapes are bytes the reader never
	// sees, and counting them would break the line onto two on a terminal wide
	// enough for it.
	if len(score)+3+len(counts) <= width {
		line(w, "%s   %s", head, painted)
	} else {
		// Four counts of four digits each is 46 columns, which fits inside the
		// narrowest width Width reports, so this never needs wrapping again.
		line(w, "%s", head)
		line(w, "      %s", painted)
	}

	// The bridge between the two countings this page uses. The line above
	// counts findings — one control against one resource — and the Findings
	// table below has one row per control; a reader meeting "23 failed" over
	// a ten-row table cannot reconcile them without this. Worded exactly as
	// the process's closing line words it, so top and bottom agree.
	if controls := failedControls(rep.Findings); controls > 0 {
		text := fmt.Sprintf("%s failed", console.Pluralize(controls, "control"))
		if s.Failed > controls {
			text += fmt.Sprintf(" across %s", console.Pluralize(s.Failed, "finding"))
		}
		summaryLine(w, p, width, ansiDim, text)
	}

	summaryLine(w, p, width, ansiDim, fmt.Sprintf(
		"weighted %d/%d (HIGH=3, MEDIUM=2, LOW=1; manual and n/a excluded)",
		s.EarnedWeight, s.TotalWeight,
	))

	// How much of the instance the score is actually based on.
	//
	// Excluding MANUAL from both sides of the fraction is right control by
	// control — an instance should not be marked down for a question its API
	// cannot answer — and misleading in aggregate, because it shrinks the
	// denominator. A token that could read a tenth of an instance scored 78
	// where a working one scored 53. This is the line that says the sample was
	// small, and it turns yellow when most of the instance went unseen.
	if scored := s.Passed + s.Failed; s.Manual > 0 {
		decidable := scored + s.Manual
		coverage := scored * 100 / decidable
		colour := ansiDim
		if coverage < 50 {
			colour = ansiYellow
		}
		summaryLine(w, p, width, colour, fmt.Sprintf(
			"scored %d of %d findings (%d%%); %d could not be evaluated",
			scored, decidable, coverage, s.Manual))
	}
}

// failedControls counts the distinct controls with at least one failure —
// the number the closing exit line reports, restated here so the report's
// first numbers and its last one use the same arithmetic.
func failedControls(findings []engine.Finding) int {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Status == engine.StatusFail {
			seen[f.CheckID] = true
		}
	}
	return len(seen)
}

// summaryLine writes one indented, wrapped line of the summary block.
//
// Colour goes on after wrapping, one line at a time. An escape sequence is
// width the reader never sees, so measuring a coloured string breaks the line
// early on a terminal that had room for it.
func summaryLine(w io.Writer, p painter, width int, colour, text string) {
	const indent = 6
	for _, l := range console.Wrap(text, width-indent) {
		line(w, "%s%s", strings.Repeat(" ", indent), p.paint(colour, l))
	}
}

// unread reports whether a finding is a control the tool would normally decide
// but could not, as opposed to one no API can answer.
//
// Both are MANUAL, and treating them as one state is what made the sample
// instance report nineteen controls needing a person when six of them did. The
// other thirteen were one unreadable job. Automated is the metadata that
// already knows the difference: false means the control is documented as
// unanswerable and always reports MANUAL; true means this run in particular
// came up short.
//
// This is a rendering distinction only. The JSON and the SARIF both still say
// MANUAL, because that is what the control returned.
func unread(f engine.Finding) bool {
	return f.Status == engine.StatusManual && f.Automated
}

// Status labels as they appear in the Status column.
const (
	statusFail   = "FAIL"
	statusUnread = "UNREAD"
	statusManual = "MANUAL"
	statusPass   = "PASS"
	statusNA     = "N/A"
)

func statusLabel(f engine.Finding) string {
	switch {
	case f.Status == engine.StatusFail:
		return statusFail
	case unread(f):
		return statusUnread
	case f.Status == engine.StatusManual:
		return statusManual
	case f.Status == engine.StatusPass:
		return statusPass
	default:
		return statusNA
	}
}

func statusColour(p painter) func(string) string {
	return func(s string) string {
		switch s {
		case statusFail:
			return p.paint(ansiRed, s)
		case statusUnread, statusManual:
			return p.paint(ansiYellow, s)
		case statusPass:
			return p.paint(ansiGreen, s)
		default:
			return p.paint(ansiDim, s)
		}
	}
}

func severityColour(p painter) func(string) string {
	return func(s string) string {
		switch strings.ToUpper(s) {
		case checks.SeverityHigh:
			return p.paint(ansiRed, s)
		case checks.SeverityMedium:
			return p.paint(ansiYellow, s)
		default:
			return p.paint(ansiDim, s)
		}
	}
}

// resourceTally is one row of the report summary: a resource and how its
// controls came out.
type resourceTally struct {
	name   string
	kind   string
	failed int
	unread int
	manual int
	passed int
	na     int
}

func tallyResources(findings []engine.Finding) []resourceTally {
	index := map[string]int{}
	var out []resourceTally
	for _, f := range findings {
		i, ok := index[f.Resource]
		if !ok {
			i = len(out)
			index[f.Resource] = i
			out = append(out, resourceTally{name: f.Resource, kind: f.ResourceType})
		}
		switch statusLabel(f) {
		case statusFail:
			out[i].failed++
		case statusUnread:
			out[i].unread++
		case statusManual:
			out[i].manual++
		case statusPass:
			out[i].passed++
		default:
			out[i].na++
		}
	}

	// Worst first, and stable between two runs that found the same thing.
	sort.Slice(out, func(a, b int) bool {
		x, y := out[a], out[b]
		switch {
		case x.failed != y.failed:
			return x.failed > y.failed
		case x.unread != y.unread:
			return x.unread > y.unread
		case x.manual != y.manual:
			return x.manual > y.manual
		}
		return x.name < y.name
	})
	return out
}

func writeWarnings(w io.Writer, rep *engine.Report, p painter, width int, withFix bool) {
	if len(rep.Metadata.Warnings) > 0 {
		blank(w)
		line(w, "%s", p.paint(ansiBold+ansiYellow, "Scan warnings"))
		blank(w)
		// One bullet per warning, with the parenthesised cause — the API path
		// and status a warning carries in brackets — dimmed, so the conclusion
		// reads before the forensics. Wrapping happens before painting, per
		// the rule everywhere else here: escapes are width the reader never
		// sees.
		unreadable := false
		for _, warning := range rep.Metadata.Warnings {
			// The phrasings the fetcher uses for an access refusal — see
			// fetcher.go's warn calls; a new phrasing there needs a match
			// here, or the fix line below silently stops printing.
			if strings.Contains(warning, "could not be read") ||
				strings.Contains(warning, "cannot read") ||
				strings.Contains(warning, "not visible") ||
				strings.Contains(warning, "not readable") {
				unreadable = true
			}
			depth := 0
			for i, l := range console.Wrap(warning, width-4) {
				prefix := "  - "
				if i > 0 {
					prefix = "    "
				}
				var painted string
				painted, depth = dimParens(p, l, depth)
				line(w, "%s%s", prefix, painted)
			}
		}
		// The failed controls all carry a fix; the scan's own blind spot is a
		// finding about the token and deserves one too. Without this line the
		// report's biggest caveat — how much went unevaluated — is the one
		// problem it never says how to solve.
		if unreadable && withFix {
			blank(w)
			prose(w, width, "  fix: ", 7,
				"rerun with a token that has administrator read access, so the scan can evaluate what it could not see.")
		}
	}
	if len(rep.Errors) > 0 {
		blank(w)
		line(w, "%s", p.paint(ansiBold+ansiRed, "Policy errors"))
		blank(w)
		for _, e := range rep.Errors {
			prose(w, width, "  ", 2, e)
		}
	}
}

// dimParens paints the parenthesised spans of one already-wrapped line dim.
// depth carries an open span across the wrapped lines of a single warning —
// the caller resets it to zero between warnings, so an unbalanced bracket
// dims at most to its own warning's end. Identity when colour is off.
func dimParens(p painter, s string, depth int) (string, int) {
	var out, seg strings.Builder
	flush := func(dim bool) {
		if seg.Len() == 0 {
			return
		}
		if dim {
			out.WriteString(p.paint(ansiDim, seg.String()))
		} else {
			out.WriteString(seg.String())
		}
		seg.Reset()
	}
	for _, r := range s {
		switch {
		case r == '(':
			if depth == 0 {
				flush(false)
			}
			depth++
			seg.WriteRune(r)
		case r == ')' && depth > 0:
			seg.WriteRune(r)
			depth--
			if depth == 0 {
				flush(true)
			}
		default:
			seg.WriteRune(r)
		}
	}
	flush(depth > 0)
	return out.String(), depth
}

// writeResourceSections is the body of the detail layout: one heading, one
// total and one table per resource, in trivy's shape. It draws only the
// findings it is handed, which is how --details filtering narrows it.
func writeResourceSections(w io.Writer, findings []engine.Finding, p painter, width int, opts Options) {
	tallies := tallyResources(findings)

	byResource := map[string][]engine.Finding{}
	for _, f := range findings {
		byResource[f.Resource] = append(byResource[f.Resource], f)
	}

	shown := 0
	skipped := 0
	for _, t := range tallies {
		selected := selectForSection(byResource[t.name], opts.ShowPassed)
		if len(selected) == 0 {
			continue
		}
		if opts.MaxResources > 0 && shown >= opts.MaxResources {
			skipped++
			continue
		}
		shown++
		writeResourceSection(w, p, width, t, selected)
	}

	if skipped > 0 {
		blank(w)
		prose(w, width, "", 0, fmt.Sprintf(
			"%s with findings not shown (--max-resources %d); use -o json for all of them.",
			console.Pluralize(skipped, "more resource"), opts.MaxResources))
	}
}

// selectForSection picks the findings a resource's table lists. A report is a
// list of things to do, so passes and not-applicables stay out of it unless
// they were asked for.
func selectForSection(findings []engine.Finding, showPassed bool) []engine.Finding {
	var out []engine.Finding
	for _, f := range findings {
		switch f.Status {
		case engine.StatusFail, engine.StatusManual:
			out = append(out, f)
		default:
			if showPassed {
				out = append(out, f)
			}
		}
	}
	return out
}

func writeResourceSection(w io.Writer, p painter, width int, t resourceTally, findings []engine.Finding) {
	blank(w)
	line(w, "%s %s", p.paint(ansiBold, t.name), p.paint(ansiDim, "("+t.kind+")"))
	blank(w)

	// Severities ascending, as trivy writes them: the reader scans right to the
	// number that decides whether this resource is tonight's problem.
	var parts []string
	for _, sev := range []string{checks.SeverityLow, checks.SeverityMedium, checks.SeverityHigh} {
		n := 0
		for _, f := range findings {
			if strings.EqualFold(f.Severity, sev) {
				n++
			}
		}
		parts = append(parts, fmt.Sprintf("%s: %d", sev, n))
	}
	line(w, "Total: %d (%s)", len(findings), strings.Join(parts, ", "))
	blank(w)

	cols := []console.Column{
		{Header: "Control", Align: console.AlignLeft,
			Colour: func(s string) string { return p.paint(ansiCyan, s) }},
		{Header: "Severity", Align: console.AlignLeft, Colour: severityColour(p)},
		{Header: "Status", Align: console.AlignLeft, Colour: statusColour(p)},
		{Header: "Title", Align: console.AlignLeft, Flex: true},
		{Header: "Finding", Align: console.AlignLeft, Flex: true},
	}

	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, []string{
			f.CheckID,
			strings.ToUpper(f.Severity),
			statusLabel(f),
			f.Title,
			findingCell(f),
		})
	}
	console.RenderTable(w, width, cols, rows)
}

// findingCell is what this resource did, what the scan saw when it looked, and
// the one move that changes it — three kinds of thing, on their own lines
// inside one cell, the way trivy puts a CVE's title and its URL together.
//
// A pass gets no fix. Telling someone how to change a setting that is already
// right reads as an instruction to go and break it, and a control the scan
// never read is not known to be wrong at all — what that one needs is access,
// which is what the scan warnings are for.
func findingCell(f engine.Finding) string {
	parts := []string{f.Details}
	for _, e := range f.Evidence {
		parts = append(parts, "· "+e)
	}
	if f.FixSummary != "" && (f.Status == engine.StatusFail || (f.Status == engine.StatusManual && !f.Automated)) {
		parts = append(parts, "fix: "+f.FixSummary)
	}
	return strings.Join(parts, "\n")
}

// writeRemediations lists the full fix for every control that needs one, once
// each.
//
// It stays prose. These are paragraphs naming settings paths, project-level
// variants and config keys, and a paragraph in a table cell is a column of
// three-word lines. trivy leaves its legend as prose for the same reason.
//
// A control that failed on one job and needs a person on another appears
// once here, not twice: the settings path is a property of the control, not of
// the verdict. Controls that merely went unread are left out — their settings
// are not known to be wrong, and printing how to change them would say
// otherwise.
//
// Two sections, because the entries ask for two different things:
// "Remediations" is settings that are wrong and how to change them; "Manual
// review" is controls no API can decide, where the ask is a person's
// judgement. One undivided list read as ten broken things when six were.
func writeRemediations(w io.Writer, findings []engine.Finding, p painter, width int) {
	ordered := remediationOrder(findings)
	if len(ordered) == 0 {
		return
	}
	fails, manuals := splitRemediations(ordered)
	idWidth := remediationIDWidth(ordered)

	full := func(f engine.Finding) {
		id := f.CheckID + strings.Repeat(" ", idWidth-len(f.CheckID))
		prose(w, width, "  "+p.paint(ansiCyan+ansiBold, id)+"  ", idWidth+4, f.Remediation)
	}
	writeRemediationSection(w, p, "Remediations", fails, full)
	writeRemediationSection(w, p, "Manual review", manuals, full)
}

// writeRulesIndex is the default layout's closing reference: one line per
// failed or manual control, its documentation link dim beside it — the fix
// already rode with each finding, so all that belongs here is where to read
// more, and the one hint a single record cannot carry: a control failing on
// every job is one folder-level setting, not N job-level ones.
func writeRulesIndex(w io.Writer, rep *engine.Report, p painter, width int) {
	ordered := remediationOrder(rep.Findings)
	sweeps := fullSweeps(rep.Findings)

	type entry struct {
		id, ref, sweep string
	}
	var entries []entry
	idWidth := 0
	for _, f := range ordered {
		e := entry{id: f.CheckID, ref: referenceLine(f.References)}
		if n := sweeps[f.CheckID]; n > 1 && strings.Contains(f.Remediation, "Folder settings") {
			e.sweep = fmt.Sprintf("failing on all %d jobs — setting it once at the folder level covers them together.", n)
		}
		if e.ref == "" && e.sweep == "" {
			// A line carrying only its own ID says nothing; the ID is already
			// on the finding above.
			continue
		}
		if len(e.id) > idWidth {
			idWidth = len(e.id)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return
	}

	blank(w)
	line(w, "%s", p.paint(ansiBold, "Rules"))
	blank(w)
	for _, e := range entries {
		pad := strings.Repeat(" ", idWidth-len(e.id))
		if e.ref != "" {
			// The link is one unbreakable token, printed whole even past the
			// width — the same policy writeHeader applies to the base URL.
			line(w, "  %s%s  %s", p.paint(ansiCyan+ansiBold, e.id), pad, p.paint(ansiDim, e.ref))
			if e.sweep != "" {
				prose(w, width, strings.Repeat(" ", idWidth+4), idWidth+4, e.sweep)
			}
			continue
		}
		prose(w, width, "  "+p.paint(ansiCyan+ansiBold, e.id)+pad+"  ", idWidth+4, e.sweep)
	}
}

func writeRemediationSection(w io.Writer, p painter, heading string, entries []engine.Finding, entry func(engine.Finding)) {
	if len(entries) == 0 {
		return
	}
	blank(w)
	line(w, "%s", p.paint(ansiBold, fmt.Sprintf("%s (%d)", heading, len(entries))))
	blank(w)
	for _, f := range entries {
		entry(f)
	}
}

// splitRemediations divides the ordered controls by what they ask of the
// reader: a changed setting, or a judgement.
func splitRemediations(ordered []engine.Finding) (fails, manuals []engine.Finding) {
	for _, f := range ordered {
		if f.Status == engine.StatusFail {
			fails = append(fails, f)
		} else {
			manuals = append(manuals, f)
		}
	}
	return fails, manuals
}

// fullSweeps maps CheckID to the job count for controls that failed on every
// job they were evaluated against — the shape where one folder-level setting
// fixes the whole row. Instance-level controls and partial rows are absent.
func fullSweeps(findings []engine.Finding) map[string]int {
	type tally struct {
		applicable, failed int
		instance           bool
	}
	tallies := map[string]*tally{}
	for _, f := range findings {
		if f.Status == engine.StatusNA {
			continue
		}
		t, ok := tallies[f.CheckID]
		if !ok {
			t = &tally{}
			tallies[f.CheckID] = t
		}
		t.applicable++
		if f.Status == engine.StatusFail {
			t.failed++
		}
		if f.Resource == engine.InstanceResourceName {
			t.instance = true
		}
	}
	sweeps := map[string]int{}
	for id, t := range tallies {
		if !t.instance && t.applicable > 1 && t.failed == t.applicable {
			sweeps[id] = t.applicable
		}
	}
	return sweeps
}

// remediationOrder picks the controls the remediation sections list: FAIL or
// MANUAL, not merely unread, once per control, in report order.
func remediationOrder(findings []engine.Finding) []engine.Finding {
	seen := map[string]bool{}
	var ordered []engine.Finding
	for _, f := range findings {
		if f.Status != engine.StatusFail && f.Status != engine.StatusManual {
			continue
		}
		if unread(f) || seen[f.CheckID] {
			continue
		}
		seen[f.CheckID] = true
		ordered = append(ordered, f)
	}
	return ordered
}

func remediationIDWidth(ordered []engine.Finding) int {
	idWidth := 0
	for _, f := range ordered {
		if n := len(f.CheckID); n > idWidth {
			idWidth = n
		}
	}
	return idWidth
}

// fixLine is the one-line remediation. Every bundled control carries a
// FixSummary; the fallbacks cover a control that does not, cutting the full
// remediation at its first sentence rather than printing the paragraph the
// summary layout exists to avoid.
func fixLine(f engine.Finding) string {
	if f.FixSummary != "" {
		return f.FixSummary
	}
	if head, _, ok := strings.Cut(f.Remediation, ". "); ok {
		return head + "."
	}
	return f.Remediation
}

// referenceLine picks the one link worth a line: the first reference that is
// not the generic CIS benchmark landing page. Every control carries that page
// and it identifies none of them, so a control with nothing else gets no link
// rather than a decorative one. SARIF keeps using References[0] as helpURI;
// this choice is about what a person scans, not what a tool ingests.
func referenceLine(refs []string) string {
	for _, r := range refs {
		if !strings.Contains(r, "cisecurity.org") {
			return r
		}
	}
	return ""
}

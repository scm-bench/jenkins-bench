// Package console renders what the tool puts on a terminal: tables, wrapped
// prose, colour, and the tagged lines it writes about itself.
//
// It exists because several separate things write to the terminal — scan's
// report, diff's report, the scan trace — and they have to look like one
// program. The table renderer, the tag vocabulary and the colours were defined
// separately before, which is exactly the arrangement that drifts: nothing
// fails when one side gains a tag or changes a border, the output just quietly
// stops lining up.
//
// Two shapes live here, and they do not overlap. Stdout is tables and prose:
// that is the report, and it is the thing a person reads. Stderr is tagged
// lines: that is the tool talking about itself, read interleaved with whatever
// else is on the terminal, where a bracketed word at the start of a line is
// what separates one program's voice from another's.
package console

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// ANSI codes, applied only when the destination is a terminal.
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)

// Painter applies colour, or does not.
type Painter struct{ Enabled bool }

func (p Painter) Paint(code, s string) string {
	if !p.Enabled || s == "" {
		return s
	}
	return code + s + Reset
}

// A Tag is the bracketed word in column one of a line on stderr.
//
// It used to lead every line of the report too. That ended when the report
// became tables: a table has borders and headers of its own, and a tag column
// bolted to the left of them is a second grid arguing with the first. What
// stayed tagged is everything the tool says *about itself* — the request trace,
// the scan warnings, the line explaining an exit code — all of which goes to
// stderr, is read interleaved with other programs' output, and has no table to
// belong to.
//
// The width is fixed so the messages line up down the page whichever tag they
// carry, and the tag is anchored at the start of the line so
// `jenkins-bench scan 2>/dev/null` and `2>&1 | grep '^\[WARN\]'` both still say
// something useful. Colour reinforces the tag but is never the only signal —
// the text survives NO_COLOR, a pipe, and a redirect to a file.
type Tag struct {
	Text  string
	Color string
}

// Four tags. An earlier version had seven — PASS, FAIL, NOTE, N/A, INFO, WARN
// and ERR — which is more vocabulary than a reader can hold while skimming, and
// the extra three were distinctions the reader could not act on differently
// anyway.
var (
	Pass = Tag{"PASS", Green}
	Fail = Tag{"FAIL", Red}
	// Warn is everything that needs a person but is not a failure: an endpoint
	// the scan could not read, an interrupted run.
	Warn = Tag{"WARN", Yellow}
	// Info is context — the request trace, and the line that explains a
	// findings exit. Nothing here is asking anything of the reader.
	Info = Tag{"INFO", Cyan}
)

// Render returns the tag as it appears in column one.
func (p Painter) Render(t Tag) string { return p.Paint(t.Color, "["+t.Text+"]") }

// Writer writes lines that all begin with a tag column.
type Writer struct {
	W io.Writer
	P Painter
}

func (w Writer) Line(t Tag, format string, args ...any) {
	fmt.Fprintf(w.W, "%s %s\n", w.P.Render(t), fmt.Sprintf(format, args...))
}

// Pluralize renders a count with its noun, adding "s" for anything but one.
//
// It lives here rather than in either command because both need it and they
// must not disagree: the scan report went to the trouble of writing real
// grammar instead of "1 control(s)", and diff was writing "control(s)" three
// files away. A shared helper is how that stops drifting.
func Pluralize(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// Blank separates blocks. It is deliberately a real empty line rather than a
// bare "[INFO]": the tag column exists to be scanned down, and a column of tags
// attached to nothing makes that harder, not easier.
func (w Writer) Blank() { fmt.Fprintln(w.W) }

// Four is the whole vocabulary. Exported for the test that holds it there — a
// fifth tag should be a decision someone makes on purpose, not something that
// accumulates.
func Tags() []Tag { return []Tag{Pass, Fail, Warn, Info} }

// Width limits are deliberately narrow. 80 is what a pipe, a CI log and an
// unconfigured terminal all are; the ceiling is where a line stops being
// comfortable to read regardless of how wide the window is.
//
// The ceiling constrains prose, not tables: a flexed column never grows past
// its content, so on a wide terminal a table stops at its natural width
// rather than sprawling. What the ceiling has to be wide enough for is a
// table's longest single-line cell — the longest control title needs 128
// columns of frame to sit on one line — and what it has to be narrow enough
// for is a wrapped remediation staying scannable under its hanging indent.
// 160 clears the first and has not yet hurt the second.
const (
	fallbackWidth = 80
	minWidth      = 60
	maxWidth      = 160
)

// Width reports how wide a rendered line may be, from the environment alone.
//
// It reads only COLUMNS, so it is deterministic wherever no terminal is
// attached — which is what the rendering tests rely on. Callers that hold the
// real output should prefer WidthFor, which also asks the terminal itself.
func Width() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return clampWidth(n)
	}
	return fallbackWidth
}

// WidthFor reports how wide a rendered line may be on the given output.
//
// An exported COLUMNS wins, because it is the one explicit statement of intent
// a user can make and the only handle the tests have. Otherwise the terminal
// is asked directly: most shells do not export COLUMNS, and defaulting a
// 200-column window to 80 wrapped every table cell for no reason. There is no
// separate is-this-a-terminal check — the size ioctl fails on pipes, regular
// files and /dev/null, which is exactly the discrimination needed. Anything
// that is not a terminal gets 80, the right answer for a pipe, a CI log and a
// report written to a file.
func WidthFor(out io.Writer) int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return clampWidth(n)
	}
	if f, ok := out.(*os.File); ok {
		if w, _, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return clampWidth(w)
		}
	}
	return fallbackWidth
}

func clampWidth(w int) int {
	if w < minWidth {
		return minWidth
	}
	if w > maxWidth {
		return maxWidth
	}
	return w
}

// Wrap breaks s into lines of at most width columns, returning at least one
// line. The caller supplies the width already reduced by whatever prefix and
// indent it intends to put in front, and indents the continuations itself, so
// the text keeps a straight left edge.
//
// It must be called before any colour is applied: an escape sequence is bytes
// the reader never sees, and counting it as width is what made the request
// trace's columns drift before it padded by hand.
//
// A word longer than width is left whole on its own line rather than split. The
// long words here are settings paths, config keys and URLs, and a reader who
// cannot select one of those in a double click has lost more than the ragged
// right margin cost them.
func Wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	if width <= 0 {
		return []string{strings.Join(words, " ")}
	}

	var lines []string
	line := words[0]
	used := utf8.RuneCountInString(line)
	for _, word := range words[1:] {
		n := utf8.RuneCountInString(word)
		if used+1+n > width {
			lines = append(lines, line)
			line, used = word, n
			continue
		}
		line += " " + word
		used += 1 + n
	}
	return append(lines, line)
}

package console

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// The tag column is still a contract, on stderr: `jenkins-bench scan 2>&1 | grep
// '^\[WARN\]'` answers "what did this scan fail to see", and it only works if
// every tag is the same width and the brackets are literal.
func TestEveryTagIsFourCharactersWide(t *testing.T) {
	for _, tag := range Tags() {
		if len(tag.Text) != 4 {
			t.Errorf("tag %q is %d characters, want 4 so the column never shifts", tag.Text, len(tag.Text))
		}
		if got := (Painter{}).Render(tag); got != "["+tag.Text+"]" {
			t.Errorf("Render(%q) = %q", tag.Text, got)
		}
	}
}

// Four is the whole vocabulary. A fifth should be a decision someone makes on
// purpose, not something that accumulates.
func TestTheVocabularyIsExactlyFour(t *testing.T) {
	seen := map[string]bool{}
	for _, tag := range Tags() {
		if seen[tag.Text] {
			t.Errorf("duplicate tag %q", tag.Text)
		}
		seen[tag.Text] = true
	}
	if len(seen) != 4 {
		t.Errorf("vocabulary has %d tags, want 4", len(seen))
	}
}

// Colour is a reinforcement, never the signal. Everything the reader needs has
// to survive a pipe, a redirect, and NO_COLOR.
func TestDisabledPainterEmitsNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	w := Writer{W: &buf, P: Painter{Enabled: false}}
	w.Line(Fail, "CIS-1.1.15 %s", w.P.Paint(Red, "HIGH"))
	w.Blank()

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Errorf("escapes leaked with colour disabled: %q", out)
	}
	if !strings.HasPrefix(out, "[FAIL] CIS-1.1.15 HIGH\n") {
		t.Errorf("unexpected line: %q", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("Blank should write a real empty line, got %q", out)
	}
}

func TestEnabledPainterWrapsAndResets(t *testing.T) {
	p := Painter{Enabled: true}
	if got := p.Render(Pass); got != Green+"[PASS]"+Reset {
		t.Errorf("Render = %q", got)
	}
	// An empty string is left alone: wrapping nothing in escapes produces a
	// stray reset that shows up as a blank in some terminals.
	if got := p.Paint(Red, ""); got != "" {
		t.Errorf("Paint of an empty string = %q, want it untouched", got)
	}
}

func TestWrapKeepsEveryLineWithinTheWidth(t *testing.T) {
	const text = "Repository settings -> Branch permissions -> Add restriction: " +
		"select the default branch and enable Prevent rewriting history."
	for _, width := range []int{20, 40, 62, 200} {
		lines := Wrap(text, width)
		for _, line := range lines {
			if n := utf8.RuneCountInString(line); n > width {
				t.Errorf("width %d: line of %d runes: %q", width, n, line)
			}
		}
		if got := strings.Join(lines, " "); got != text {
			t.Errorf("width %d: rejoined text changed:\n got %q\nwant %q", width, got, text)
		}
	}
}

// Settings paths, config keys and URLs are the long words here, and a reader
// who cannot double click one of them has lost more than the ragged margin cost.
func TestWrapLeavesAWordTooLongToFitWhole(t *testing.T) {
	lines := Wrap("set thresholds.inactiveUserDays in config", 10)
	for _, line := range lines {
		if strings.Contains(line, "thresholds.inactiveUserDays") {
			return
		}
	}
	t.Errorf("the long word was split across %q", lines)
}

// Callers index lines[0] unconditionally, so Wrap owes them a line even for
// text that is empty or all spaces.
func TestWrapAlwaysReturnsALine(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		if got := Wrap(in, 40); len(got) != 1 || got[0] != "" {
			t.Errorf("Wrap(%q) = %#v, want one empty line", in, got)
		}
	}
	if got := Wrap("two words", 0); len(got) != 1 || got[0] != "two words" {
		t.Errorf("Wrap with a non-positive width = %#v, want the text unbroken", got)
	}
}

func TestWidthIsClampedAndDefaultsToEighty(t *testing.T) {
	for _, tc := range []struct {
		columns string
		want    int
	}{
		{"", fallbackWidth},
		{"not a number", fallbackWidth},
		{"0", fallbackWidth},
		{"-10", fallbackWidth},
		{"20", minWidth},
		{"90", 90},
		{"400", maxWidth},
	} {
		t.Setenv("COLUMNS", tc.columns)
		if got := Width(); got != tc.want {
			t.Errorf("COLUMNS=%q: Width() = %d, want %d", tc.columns, got, tc.want)
		}
	}
}

// WidthFor asks the terminal only when the environment has not spoken and the
// output could actually be one. Neither is true anywhere a test can run, so
// the tty-success branch stays untested by design — it is two lines.
func TestWidthForPrefersColumnsThenTerminal(t *testing.T) {
	var buf bytes.Buffer
	for _, tc := range []struct {
		columns string
		want    int
	}{
		{"100", 100},
		{"300", maxWidth},
		{"20", minWidth},
		{"", fallbackWidth},
		{"junk", fallbackWidth},
		{"0", fallbackWidth},
	} {
		t.Setenv("COLUMNS", tc.columns)
		if got := WidthFor(&buf); got != tc.want {
			t.Errorf("COLUMNS=%q: WidthFor(buffer) = %d, want %d", tc.columns, got, tc.want)
		}
	}

	// Real files that are not terminals: the size ioctl fails on them, which
	// is the whole discrimination — no separate is-a-terminal check exists.
	t.Setenv("COLUMNS", "")
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if got := WidthFor(f); got != fallbackWidth {
		t.Errorf("WidthFor(regular file) = %d, want %d", got, fallbackWidth)
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open %s: %v", os.DevNull, err)
	}
	defer null.Close()
	if got := WidthFor(null); got != fallbackWidth {
		t.Errorf("WidthFor(%s) = %d, want %d", os.DevNull, got, fallbackWidth)
	}
}

// A border that is not straight stops reading as a border, so nothing a table
// draws may exceed the width it was given — at any width, with or without
// colour, however long the words in a cell are.
func TestTableNeverExceedsItsWidth(t *testing.T) {
	cols := []Column{
		{Header: "Control", Align: AlignLeft},
		{Header: "Severity", Align: AlignLeft, Colour: func(s string) string { return Red + s + Reset }},
		{Header: "Title", Align: AlignLeft, Flex: true},
		{Header: "Finding", Align: AlignLeft, Flex: true},
	}
	rows := [][]string{
		{"CIS-1.1.3", "HIGH",
			"Ensure any change to code receives approval of two strongly authenticated users",
			"Pull requests require 0 approval(s).\n· requiredApprovers = 0\nfix: Set it at Repository settings -> Pull requests -> Merge checks."},
		// A single unbreakable run far wider than any column will be.
		{"CIS-1.2.1", "LOW", "x", strings.Repeat("thresholds.inactiveUserDays", 4)},
	}

	for _, width := range []int{60, 80, 100, 120, 200} {
		var buf bytes.Buffer
		RenderTable(&buf, width, cols, rows)
		for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
			if n := utf8.RuneCountInString(stripEscapes(line)); n > width {
				t.Errorf("width %d: line of %d columns: %q", width, n, line)
			}
		}
	}
}

// Every row of a table has to agree with every other about where the columns
// are, which is the whole reason a table is easier to read than a list.
func TestTableColumnsLineUpOnEveryRow(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 80, []Column{
		{Header: "A", Align: AlignLeft},
		{Header: "B", Align: AlignRight},
		{Header: "C", Align: AlignLeft, Flex: true},
	}, [][]string{
		{"short", "1", "a sentence long enough that it has to wrap more than once inside its cell"},
		{"a much longer value", "1234", "two\nhard\nlines"},
	})

	layouts := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		var at []int
		for i, r := range []rune(stripEscapes(line)) {
			if strings.ContainsRune("│┌┬┐├┼┤└┴┘", r) {
				at = append(at, i)
			}
		}
		layouts[fmt.Sprint(at)] = true
	}
	if len(layouts) != 1 {
		t.Errorf("got %d different column layouts, want 1:\n%s", len(layouts), buf.String())
	}
}

// Colour is width the reader never sees. Measuring it would push the border of
// a coloured row out of line with the row above it.
func TestTableColourDoesNotMoveTheBorders(t *testing.T) {
	cols := func(colour bool) []Column {
		paint := func(s string) string { return s }
		if colour {
			paint = func(s string) string { return Red + s + Reset }
		}
		return []Column{
			{Header: "Status", Align: AlignLeft, Colour: paint},
			{Header: "Detail", Align: AlignLeft, Flex: true},
		}
	}
	rows := [][]string{{"FAIL", "something went wrong here"}, {"PASS", "fine"}}

	var plain, painted bytes.Buffer
	RenderTable(&plain, 60, cols(false), rows)
	RenderTable(&painted, 60, cols(true), rows)

	if got := stripEscapes(painted.String()); got != plain.String() {
		t.Errorf("colour changed the layout:\nplain:\n%s\npainted (escapes stripped):\n%s", plain.String(), got)
	}
	if strings.Contains(plain.String(), "\033[") {
		t.Error("escapes leaked into an uncoloured table")
	}
}

// Newlines in a cell are the caller saying "these are separate things" — a
// finding's details, its evidence, its fix — and must survive as separate
// lines rather than being reflowed into one paragraph.
func TestTableKeepsHardBreaksInsideACell(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 60, []Column{{Header: "Finding", Align: AlignLeft, Flex: true}},
		[][]string{{"first\n· second\nfix: third"}})

	out := buf.String()
	for _, want := range []string{"first", "· second", "fix: third"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}
	if strings.Contains(out, "first · second") {
		t.Errorf("hard breaks were reflowed:\n%s", out)
	}
}

func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// A table of nothing but fixed columns still has to fit. Nothing absorbs the
// overflow, so the columns themselves have to give, widest first.
func TestFixedOnlyTableShrinksToFit(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 40, []Column{
		{Header: "Resource", Align: AlignLeft},
		{Header: "Type", Align: AlignLeft},
		{Header: "Failed", Align: AlignRight},
	}, [][]string{
		{"PLAT/a-very-long-repository-name-indeed", "repository", "12"},
		{"PLAT/b", "repository", "-"},
	})

	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n > 40 {
			t.Errorf("line of %d columns exceeds the width: %q", n, line)
		}
	}
	if !strings.Contains(buf.String(), "12") {
		t.Errorf("shrinking lost a value:\n%s", buf.String())
	}
}

// When the fixed columns alone would leave the flexed ones with nothing, the
// fixed ones have to give up width too — a table with a column of width zero
// is not a table.
func TestFixedColumnsGiveWayToKeepFlexedOnesReadable(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 60, []Column{
		{Header: "A very wide fixed heading indeed", Align: AlignLeft},
		{Header: "Another wide fixed heading", Align: AlignLeft},
		{Header: "Flex", Align: AlignLeft, Flex: true},
	}, [][]string{
		{"value one", "value two", "a sentence that needs somewhere to go"},
	})

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	for _, line := range lines {
		if n := utf8.RuneCountInString(line); n > 60 {
			t.Errorf("line of %d columns exceeds the width: %q", n, line)
		}
	}
	// The flexed column kept enough room to hold real words rather than one
	// letter per line.
	if !strings.Contains(buf.String(), "sentence") {
		t.Errorf("the flexed column was squeezed to nothing:\n%s", buf.String())
	}
}

// A table of short values should not be stretched across a wide window with a
// lake of padding in the middle.
func TestFlexedColumnsDoNotGrowPastTheirContent(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 200, []Column{
		{Header: "A", Align: AlignLeft},
		{Header: "B", Align: AlignLeft, Flex: true},
	}, [][]string{{"x", "y"}})

	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n > 20 {
			t.Errorf("a table of two one-character cells is %d columns wide: %q", n, line)
		}
	}
}

func TestRenderTableWithNoColumnsWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 80, nil, [][]string{{"ignored"}})
	if buf.Len() != 0 {
		t.Errorf("wrote %q for a table with no columns", buf.String())
	}
}

// Alignment is what makes a column of counts readable, so it has to survive
// padding on both sides.
func TestCellsHonourTheirAlignment(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf, 40, []Column{
		{Header: "Left", Align: AlignLeft},
		{Header: "Right", Align: AlignRight},
		{Header: "Centre", Align: AlignCentre},
	}, [][]string{{"a", "b", "c"}})

	out := buf.String()
	for _, want := range []string{"│ a    ", "│     b │", "│   c    │"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}
}

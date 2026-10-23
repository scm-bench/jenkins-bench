package console

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// A row may carry fewer cells than there are columns — a summary row, say.
// The missing cells render blank and the borders stay put.
func TestTableToleratesShortRows(t *testing.T) {
	var buf bytes.Buffer
	cols := []Column{{Header: "ID"}, {Header: "Title", Flex: true}, {Header: "Sev"}}
	RenderTable(&buf, 60, cols, [][]string{{"1.1"}, {"1.2", "a title", "HIGH"}})
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	want := utf8.RuneCountInString(lines[0])
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n != want {
			t.Errorf("line is %d wide, want %d: %q", n, want, l)
		}
	}
	if !strings.Contains(buf.String(), "HIGH") {
		t.Errorf("the full row went missing:\n%s", buf.String())
	}
}

// A blank line inside a cell is a deliberate gap between paragraphs, not
// something to wrap away.
func TestTableKeepsBlankLinesInsideACell(t *testing.T) {
	got := layout("first\n\nsecond", 20)
	want := []string{"first", "", "second"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("layout = %q, want %q", got, want)
	}
}

// On a terminal too narrow for anything, the table still draws: every column
// keeps at least one character rather than collapsing to zero or below.
func TestTableOnAnAbsurdlyNarrowTerminal(t *testing.T) {
	for _, cols := range [][]Column{
		{{Header: "Resource"}, {Header: "Finding", Flex: true}},
		{{Header: "Resource"}, {Header: "Type"}},
	} {
		var buf bytes.Buffer
		RenderTable(&buf, 4, cols, [][]string{{"PLAT/a-long-name", "repository"}})
		if !strings.Contains(buf.String(), "┌") {
			t.Fatalf("no table drawn:\n%s", buf.String())
		}
		widths := columnWidths(4, cols, [][]string{{"PLAT/a-long-name", "repository"}})
		for i, w := range widths {
			if w < 1 {
				t.Errorf("column %d has width %d", i, w)
			}
		}
	}
}

func TestBreakLongWordWithNoRoomLeavesTheWordWhole(t *testing.T) {
	for _, w := range []int{0, -3} {
		if got := breakLongWord("settings.path", w); len(got) != 1 || got[0] != "settings.path" {
			t.Errorf("breakLongWord(width %d) = %q, want the word unchanged", w, got)
		}
	}
}

// padded must not panic (strings.Repeat with a negative count does) when a
// caller hands it more text than the field holds; the text simply overflows.
func TestPaddedOverflowsRatherThanPanicking(t *testing.T) {
	for _, a := range []Align{AlignLeft, AlignCentre, AlignRight} {
		if got := padded("too long for it", 3, a, nil); got != "too long for it" {
			t.Errorf("padded(align %d) = %q", a, got)
		}
	}
}

func TestPluralize(t *testing.T) {
	for n, want := range map[int]string{0: "0 controls", 1: "1 control", 2: "2 controls"} {
		if got := Pluralize(n, "control"); got != want {
			t.Errorf("Pluralize(%d) = %q, want %q", n, got, want)
		}
	}
}

// Two flexed columns sharing an odd number of spare characters: the first one
// takes the odd character, and the total still fills the budget exactly.
func TestFlexedColumnsSplitAnOddRemainder(t *testing.T) {
	long := strings.Repeat("word ", 40)
	cols := []Column{{Header: "A", Flex: true}, {Header: "B", Flex: true}}
	// overhead = 3 borders + 4 padding = 7; budget 30 - 7 = 23 = 12 + 11.
	widths := columnWidths(30, cols, [][]string{{long, long}})
	if widths[0] != 12 || widths[1] != 11 {
		t.Errorf("widths = %v, want [12 11]", widths)
	}
}

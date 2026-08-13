package console

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Align is how a cell sits in its column.
type Align int

const (
	AlignLeft Align = iota
	AlignCentre
	AlignRight
)

// A Column describes one column of a rendered table.
type Column struct {
	Header string
	Align  Align
	// Flex marks a column that absorbs whatever width is left after the fixed
	// columns have taken what their content needs. Control IDs and severities
	// are a known handful of characters wide; titles and findings are prose and
	// will use everything they are given, so they are the ones that flex.
	Flex bool
	// Colour paints a cell's text. It is applied after the text has been
	// wrapped and measured, never before: an escape sequence is bytes the
	// reader never sees, and counting them as width is what pushes a border out
	// of line with the row above it.
	Colour func(string) string
}

// Table border characters, the same set trivy draws with.
const (
	borderH  = "─"
	borderV  = "│"
	cornerTL = "┌"
	cornerTR = "┐"
	cornerBL = "└"
	cornerBR = "┘"
	teeT     = "┬"
	teeB     = "┴"
	teeL     = "├"
	teeR     = "┤"
	cross    = "┼"
)

// cellPadding is the space either side of a cell's text, so a column of width n
// occupies n+2 columns of the terminal.
const cellPadding = 2

// minFlexWidth keeps a flexed column readable. Below about this, wrapping
// degrades into one word per line and the table stops being a table.
const minFlexWidth = 8

// RenderTable draws rows under cols, fitting the whole table inside width.
//
// A cell may contain newlines, which are kept as hard breaks — that is how a
// finding puts its details, its evidence and its fix on separate lines inside
// one cell. Anything still too wide is soft-wrapped by Wrap.
//
// Cells are never merged the way trivy merges repeated values down a column.
// Merging saves vertical space and costs the reader a row that no longer says
// what it belongs to; the table is dense enough without it.
func RenderTable(w io.Writer, width int, cols []Column, rows [][]string) {
	if len(cols) == 0 {
		return
	}
	widths := columnWidths(width, cols, rows)

	fmt.Fprintln(w, rule(cornerTL, teeT, cornerTR, widths))
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.Header
	}
	// Headers are centred whatever the column's alignment is, which is what
	// trivy does and what makes a narrow numeric column read as a heading
	// rather than as another value.
	writeRow(w, widths, cols, headers, true)
	fmt.Fprintln(w, rule(teeL, cross, teeR, widths))

	for i, row := range rows {
		if i > 0 {
			fmt.Fprintln(w, rule(teeL, cross, teeR, widths))
		}
		writeRow(w, widths, cols, row, false)
	}
	fmt.Fprintln(w, rule(cornerBL, teeB, cornerBR, widths))
}

// columnWidths gives every fixed column what its widest line needs and splits
// what is left between the flexed ones.
//
// When even that does not fit — a very narrow terminal, or a fixed column with
// unusually long content — the fixed columns are shaved in turn, widest first,
// until the flexed columns can have their minimum. The table gets ugly before
// it gets wider than the terminal, because a border that wraps stops looking
// like a border at all.
func columnWidths(width int, cols []Column, rows [][]string) []int {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = displayWidth(c.Header)
	}
	for _, row := range rows {
		for i := range cols {
			if i >= len(row) {
				continue
			}
			for _, line := range strings.Split(row[i], "\n") {
				if n := displayWidth(line); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}

	// Borders and padding: one vertical rule per column plus a closing one,
	// and cellPadding inside every cell.
	overhead := len(cols) + 1 + len(cols)*cellPadding
	budget := width - overhead

	var flex []int
	fixedTotal := 0
	for i, c := range cols {
		if c.Flex {
			flex = append(flex, i)
			continue
		}
		fixedTotal += widths[i]
	}

	if len(flex) == 0 {
		shrinkTo(widths, budget, 1)
		return widths
	}

	// Shave the fixed columns only if the flexed ones cannot otherwise reach
	// their minimum.
	if need := len(flex) * minFlexWidth; budget-fixedTotal < need {
		fixed := make([]int, 0, len(cols))
		for i, c := range cols {
			if !c.Flex {
				fixed = append(fixed, i)
			}
		}
		shrinkSelected(widths, fixed, budget-need, 1)
		fixedTotal = 0
		for _, i := range fixed {
			fixedTotal += widths[i]
		}
	}

	remaining := budget - fixedTotal
	if remaining < len(flex) {
		remaining = len(flex) // one column each; the terminal is absurdly narrow
	}
	share, extra := remaining/len(flex), remaining%len(flex)
	for n, i := range flex {
		widths[i] = share
		if n < extra {
			widths[i]++
		}
		// A flexed column never grows past what its content actually needs;
		// otherwise a table of short values gets stretched across the window
		// with a lake of padding in the middle.
		if natural := naturalWidth(cols, rows, i); widths[i] > natural && natural > 0 {
			widths[i] = natural
		}
	}
	return widths
}

func naturalWidth(cols []Column, rows [][]string, col int) int {
	n := displayWidth(cols[col].Header)
	for _, row := range rows {
		if col >= len(row) {
			continue
		}
		for _, line := range strings.Split(row[col], "\n") {
			if w := displayWidth(line); w > n {
				n = w
			}
		}
	}
	return n
}

// shrinkTo reduces every column proportionally until they sum to at most total.
func shrinkTo(widths []int, total, floor int) {
	all := make([]int, len(widths))
	for i := range widths {
		all[i] = i
	}
	shrinkSelected(widths, all, total, floor)
}

// shrinkSelected takes width off the listed columns, always from the widest, so
// one long value gives ground before several short ones do.
func shrinkSelected(widths []int, cols []int, total, floor int) {
	sum := 0
	for _, i := range cols {
		sum += widths[i]
	}
	for sum > total {
		widest, at := 0, -1
		for _, i := range cols {
			if widths[i] > widest {
				widest, at = widths[i], i
			}
		}
		if at < 0 || widths[at] <= floor {
			return
		}
		widths[at]--
		sum--
	}
}

func rule(left, mid, right string, widths []int) string {
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		if i > 0 {
			b.WriteString(mid)
		}
		b.WriteString(strings.Repeat(borderH, w+cellPadding))
	}
	b.WriteString(right)
	return b.String()
}

// writeRow lays one row out over as many terminal lines as its tallest cell
// needs, padding the shorter cells with blanks so the borders stay vertical.
func writeRow(w io.Writer, widths []int, cols []Column, row []string, header bool) {
	cells := make([][]string, len(cols))
	height := 1
	for i := range cols {
		text := ""
		if i < len(row) {
			text = row[i]
		}
		cells[i] = layout(text, widths[i])
		if len(cells[i]) > height {
			height = len(cells[i])
		}
	}

	for line := 0; line < height; line++ {
		var b strings.Builder
		b.WriteString(borderV)
		for i, c := range cols {
			text := ""
			if line < len(cells[i]) {
				text = cells[i][line]
			}
			align := c.Align
			if header {
				align = AlignCentre
			}
			b.WriteString(" ")
			b.WriteString(padded(text, widths[i], align, colourOf(c, header)))
			b.WriteString(" ")
			b.WriteString(borderV)
		}
		fmt.Fprintln(w, b.String())
	}
}

func colourOf(c Column, header bool) func(string) string {
	if header || c.Colour == nil {
		return nil
	}
	return c.Colour
}

// layout turns a cell's text into the lines it occupies, keeping newlines as
// hard breaks and soft-wrapping whatever is still too wide.
func layout(text string, width int) []string {
	var out []string
	for _, hard := range strings.Split(text, "\n") {
		if strings.TrimSpace(hard) == "" {
			out = append(out, "")
			continue
		}
		for _, soft := range Wrap(hard, width) {
			out = append(out, breakLongWord(soft, width)...)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// breakLongWord splits a run no space could break — a settings path, a config
// key, a URL — at the column edge.
//
// Wrap deliberately leaves those whole, because in prose an overlong line only
// looks ragged and a reader who cannot double click a path has lost more than
// the margin was worth. Inside a table the same line pushes the border out of
// true for that row, and a border that is not straight stops reading as a
// border at all. Here the column wins.
func breakLongWord(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	r := []rune(s)
	if len(r) <= width {
		return []string{s}
	}
	var out []string
	for len(r) > width {
		out = append(out, string(r[:width]))
		r = r[width:]
	}
	return append(out, string(r))
}

// padded aligns text in a field of the given width, colouring only the text so
// the padding cannot carry an escape sequence into the border.
func padded(text string, width int, align Align, colour func(string) string) string {
	gap := width - displayWidth(text)
	if gap < 0 {
		gap = 0
	}
	if colour != nil && text != "" {
		text = colour(text)
	}
	switch align {
	case AlignRight:
		return strings.Repeat(" ", gap) + text
	case AlignCentre:
		left := gap / 2
		return strings.Repeat(" ", left) + text + strings.Repeat(" ", gap-left)
	default:
		return text + strings.Repeat(" ", gap)
	}
}

func displayWidth(s string) int { return utf8.RuneCountInString(s) }

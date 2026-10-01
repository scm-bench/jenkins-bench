package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// progressWriter renders one self-overwriting status line on stderr while a
// scan runs.
//
// Only on a terminal. A redirected stream has no cursor to move, so carriage
// returns would pile up as thousands of lines in a CI log — the opposite of the
// point; there the accounting line at the end is the whole story. And not with
// --verbose, whose request lines would interleave with it.
type progressWriter struct {
	out io.Writer

	// requests counts completed HTTP requests, fed by the client's request
	// events from every fetch goroutine.
	requests atomic.Int64

	mu    sync.Mutex
	last  int
	text  string
	frame int

	stop chan struct{}
	done chan struct{}
}

// spinnerFrames is the classic four-frame rotor, in ASCII: this goes to
// whatever terminal is attached, and a spinner drawn as boxes is worse than
// none.
const spinnerFrames = `|/-\`

// spinnerInterval is how often the rotor turns on its own. Time-driven rather
// than request-driven, so it keeps moving through a slow request — exactly the
// moment someone starts wondering whether the scan is stuck.
const spinnerInterval = 120 * time.Millisecond

// newProgressWriter returns a writer for stderr, or nil when progress should
// not be shown. Every method is safe on nil.
func newProgressWriter(out io.Writer, enabled bool) *progressWriter {
	if !enabled || !isTerminal(out) {
		return nil
	}
	return &progressWriter{out: out}
}

// start draws the line and turns the rotor until clear.
func (p *progressWriter) start() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.stop != nil {
		p.mu.Unlock()
		return
	}
	// Locals: clear nils the fields before closing, so the goroutine must
	// not read them back through p.
	stop := make(chan struct{})
	done := make(chan struct{})
	p.stop, p.done = stop, done
	p.text = "scanning"
	p.redrawLocked()
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(spinnerInterval)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				p.frame++
				p.redrawLocked()
				p.mu.Unlock()
			}
		}
	}()
}

// tick counts one completed request. The redraw is the ticker's: a large
// controller completes requests faster than a terminal is worth repainting.
func (p *progressWriter) tick() {
	if p == nil {
		return
	}
	p.requests.Add(1)
}

// jobsRead updates the phase text from the fetcher's job counter.
func (p *progressWriter) jobsRead(done, total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.text = fmt.Sprintf("reading jobs %d/%d", done, total)
	p.redrawLocked()
}

// interrupt prints something else on stderr — a warning — with the status line
// erased first and redrawn after, so the two never share a row. On a nil
// writer it just prints.
func (p *progressWriter) interrupt(print func()) {
	if p == nil {
		print()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.last))
		p.last = 0
	}
	print()
	if p.stop != nil {
		p.redrawLocked()
	}
}

// redrawLocked repaints the line. Callers hold p.mu.
func (p *progressWriter) redrawLocked() {
	line := fmt.Sprintf("%c %s", spinnerFrames[p.frame%len(spinnerFrames)], p.text)
	if n := p.requests.Load(); n > 0 {
		line += fmt.Sprintf(" · %d requests", n)
	}
	// Padded to the previous width, in runes rather than bytes, so a shorter
	// line cannot leave the tail of a longer one behind — and a job name
	// outside ASCII does not overshoot the padding onto the next row.
	width := utf8.RuneCountInString(line)
	padding := ""
	if trailing := p.last - width; trailing > 0 {
		padding = strings.Repeat(" ", trailing)
	}
	fmt.Fprintf(p.out, "\r%s%s", line, padding)
	p.last = width
}

// clear stops the rotor and erases the line, so the report does not begin on
// a line that still holds a half-finished count.
func (p *progressWriter) clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	stop, done := p.stop, p.done
	p.stop, p.done = nil, nil
	p.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done // no draws after the erase below
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last > 0 {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.last))
		p.last = 0
	}
}

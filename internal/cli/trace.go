package cli

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/scm-bench/jenkins-bench/internal/ci/jenkins"
	"github.com/scm-bench/jenkins-bench/internal/console"
)

// tracer shows what the scan is doing, and accounts for it afterwards.
//
// The accounting is the point. This tool asks for a token that can read every
// job configuration on a controller, and its central claim is that it only
// ever reads. That claim lived in the README and in a test — neither of which
// the person handing over the token is looking at. Closing every scan with a
// count of what was actually sent, by method, turns the claim into something
// they can see, in a terminal and in a CI log alike.
type tracer struct {
	out     io.Writer
	colour  bool
	verbose bool

	mu       sync.Mutex
	total    int
	byMethod map[string]int
	retries  int
}

func newTracer(out io.Writer, colour, verbose bool) *tracer {
	return &tracer{out: out, colour: colour, verbose: verbose, byMethod: map[string]int{}}
}

func (t *tracer) paint(code, s string) string {
	if !t.colour || s == "" {
		return s
	}
	return code + s + console.Reset
}

// record accounts for one request the client sent, and with --verbose prints
// it. Called from every fetch goroutine; the lock covers the whole line.
func (t *tracer) record(e jenkins.RequestEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total++
	t.byMethod[e.Method]++
	if e.Attempt > 0 {
		t.retries++
	}
	if t.verbose {
		fmt.Fprintf(t.out, "%s %s\n", console.Painter{Enabled: t.colour}.Render(console.Info), t.formatRequest(e))
	}
}

// formatRequest renders one request: method, path, status, duration, and the
// attempt when it was a retry.
//
// Padded by hand rather than with %-4s and %-60s: on a coloured string those
// count the escape bytes, and every column after them shifts whenever colour
// is on.
func (t *tracer) formatRequest(e jenkins.RequestEvent) string {
	method := e.Method
	if method != http.MethodGet && method != http.MethodHead {
		// The one thing worth shouting about.
		method = t.paint(console.Red+console.Bold, method)
	} else {
		method = t.paint(console.Dim, method)
	}
	if n := 4 - utf8.RuneCountInString(e.Method); n > 0 {
		method += strings.Repeat(" ", n)
	}

	status := t.paint(console.Dim, "  -")
	switch {
	case e.Err != nil:
		status = t.paint(console.Red, "err")
	case e.Status >= 500:
		status = t.paint(console.Red, fmt.Sprintf("%3d", e.Status))
	case e.Status >= 400:
		// Ordinary here: a 403 is how a least-privilege token is told no,
		// and a 404 how an absent plugin answers.
		status = t.paint(console.Yellow, fmt.Sprintf("%3d", e.Status))
	case e.Status >= 300:
		status = t.paint(console.Yellow, fmt.Sprintf("%3d", e.Status))
	case e.Status > 0:
		status = t.paint(console.Green, fmt.Sprintf("%3d", e.Status))
	}

	path := e.Path
	pad := ""
	if n := 60 - utf8.RuneCountInString(path); n > 0 {
		pad = strings.Repeat(" ", n)
	}
	line := fmt.Sprintf("  %s %s%s %s %6s", method, path, pad, status, formatDuration(e.Took))
	if e.Attempt > 0 {
		line += t.paint(console.Yellow, fmt.Sprintf("  retry %d", e.Attempt))
	}
	if e.Err != nil {
		line += t.paint(console.Dim, "  "+e.Err.Error())
	}
	return line
}

// summary is the line the whole thing exists for: what was sent, and that none
// of it could have changed anything. Empty when nothing was sent — a scan of a
// snapshot on disk contacted nobody, and saying "0 requests" would suggest it
// had.
func (t *tracer) summary() (string, console.Tag) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total == 0 {
		return "", console.Info
	}

	methods := make([]string, 0, len(t.byMethod))
	for m := range t.byMethod {
		methods = append(methods, m)
	}
	sort.Strings(methods)

	writes := 0
	parts := make([]string, 0, len(methods))
	for _, m := range methods {
		parts = append(parts, fmt.Sprintf("%d %s", t.byMethod[m], m))
		if m != http.MethodGet && m != http.MethodHead {
			writes += t.byMethod[m]
		}
	}
	line := fmt.Sprintf("%s · %s", console.Pluralize(t.total, "request"), strings.Join(parts, " · "))
	if t.retries > 0 {
		line += fmt.Sprintf(" · %d retried", t.retries)
	}
	if writes > 0 {
		// Unreachable unless somebody adds a non-GET call, which the client's
		// transport refuses to send. Saying so loudly anyway beats a quiet
		// contradiction of the tool's central promise.
		return t.paint(console.Red+console.Bold, fmt.Sprintf("✗ %s · %d NOT READ-ONLY", line, writes)), console.Fail
	}
	return t.paint(console.Green, "✓ ") + t.paint(console.Dim, line+" · 0 writes · read-only"), console.Info
}

func formatDuration(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

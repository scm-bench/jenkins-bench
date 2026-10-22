package cli

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a bytes.Buffer the spinner goroutine and the test can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The rotor turns on its own, so a slow request does not look like a hang.
func TestProgressSpinsWithoutRequests(t *testing.T) {
	var buf lockedBuffer
	p := &progressWriter{out: &buf}
	p.start()
	defer p.clear()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "/ scanning") {
		if time.Now().After(deadline) {
			t.Fatalf("the spinner never advanced:\n%q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A second start is a no-op: one line, one rotor.
func TestProgressStartsOnce(t *testing.T) {
	var buf lockedBuffer
	p := &progressWriter{out: &buf}
	p.start()
	stop := p.stop
	p.start()
	if p.stop != stop {
		t.Error("a second start replaced the running rotor")
	}
	p.clear()
}

// A shorter line is padded over the tail of the longer one before it.
func TestProgressPadsAShorterLine(t *testing.T) {
	var buf bytes.Buffer
	p := &progressWriter{out: &buf}
	p.text = "reading jobs 100/100"
	p.redrawLocked()
	p.text = "scanning"
	p.redrawLocked()
	long := len("| reading jobs 100/100")
	short := len("| scanning")
	if !strings.HasSuffix(buf.String(), "\r| scanning"+strings.Repeat(" ", long-short)) {
		t.Errorf("the shorter line was not padded:\n%q", buf.String())
	}
}

func TestTraceMarksARedirect(t *testing.T) {
	tr := newTracer(&bytes.Buffer{}, false, true)
	if got := tr.formatRequest(sent(http.MethodGet, "/login", 302)); !strings.Contains(got, "302") {
		t.Errorf("formatRequest = %q, want the status", got)
	}
}

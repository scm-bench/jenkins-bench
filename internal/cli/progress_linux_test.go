//go:build linux

package cli

import (
	"os"
	"testing"
)

// On a terminal, and only when asked, progress is shown.
func TestProgressIsShownOnATerminal(t *testing.T) {
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	defer ptm.Close()
	if !isTerminal(ptm) {
		t.Fatal("a pseudo-terminal should count as a terminal")
	}
	if p := newProgressWriter(ptm, true); p == nil {
		t.Error("no progress writer on a terminal")
	}
}

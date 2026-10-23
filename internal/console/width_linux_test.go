//go:build linux

package console

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The terminal branch of WidthFor, exercised against a pseudo-terminal whose
// window size is set explicitly: what the ioctl reports is what is used.
func TestWidthForAsksTheTerminal(t *testing.T) {
	t.Setenv("COLUMNS", "")
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	defer ptm.Close()
	if err := unix.IoctlSetWinsize(int(ptm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 132, Row: 40}); err != nil {
		t.Skipf("cannot size the pseudo-terminal: %v", err)
	}
	if got := WidthFor(ptm); got != 132 {
		t.Errorf("WidthFor(pty of 132 columns) = %d, want 132", got)
	}
}

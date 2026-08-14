package cli

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestExitCodeDistinguishesFindingsFromFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"no error", nil, ExitOK},
		{"findings", &exitCodeError{code: ExitFindings, msg: "3 failures"}, ExitFindings},
		{"scan failed", errors.New("connection refused"), ExitError},
		// The coded error has to survive being wrapped, or the exit code
		// depends on whether anyone added context on the way out.
		{"wrapped findings", fmt.Errorf("scan: %w", &exitCodeError{code: ExitFindings, msg: "3 failures"}), ExitFindings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.err); got != tt.want {
				t.Errorf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestExitCodeErrorCarriesItsMessage(t *testing.T) {
	err := &exitCodeError{code: ExitFindings, msg: "2 HIGH failures"}
	if err.Error() != "2 HIGH failures" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestStderrWriterIsUsable(t *testing.T) {
	w := StderrWriter()
	if w.W != os.Stderr {
		t.Error("StderrWriter should write to stderr")
	}
}

func TestNoColorEnvIsHonoured(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if hasNoColorEnv() {
		t.Error("an empty NO_COLOR should not disable colour")
	}
	t.Setenv("NO_COLOR", "1")
	if !hasNoColorEnv() {
		t.Error("NO_COLOR should disable colour")
	}
}

func TestIsTerminalRejectsNonTerminals(t *testing.T) {
	if isTerminal(nil) {
		t.Error("a nil writer is not a terminal")
	}

	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file is not a terminal")
	}

	// /dev/null is a character device, so the mode check alone calls it a
	// terminal and the tool then paints escape codes into a redirect.
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer devnull.Close()
	if isTerminal(devnull) {
		t.Errorf("%s must not be treated as a terminal", os.DevNull)
	}
}

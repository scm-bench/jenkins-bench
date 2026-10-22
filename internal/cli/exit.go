package cli

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/scm-bench/jenkins-bench/internal/console"
)

// Run executes the command tree and returns the process's exit code. When it
// is not ExitOK, the reason is the last line on out, carrying the same tag
// column as everything above it, so a reader scanning down column one does not
// lose the thread at the one line that says why the scan stopped.
func Run(ctx context.Context, root *cobra.Command, out console.Writer) int {
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	code := ExitCode(err)
	switch {
	case errors.Is(err, context.Canceled):
		// Ctrl-C. Saying so beats exiting 2 in silence, which is
		// indistinguishable from a crash to anyone reading a log later.
		out.Line(console.Warn, "interrupted")
	case code == ExitError:
		out.Line(console.Fail, "%v", err)
	default:
		// A findings exit is a successful scan with a negative result: the
		// report has already been printed, so only a one-line summary belongs
		// on stderr. INFO, not ERR — nothing went wrong with the scan.
		out.Line(console.Info, "%v", err)
	}
	return code
}

// exitCodeError carries a specific exit code out of RunE. Exit 1 is a
// successful scan with findings; exit 2 is a scan that could not complete —
// the distinction CI most needs.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

// ExitCode extracts the process exit code from an error returned by the root
// command, defaulting to ExitError.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return ExitError
}

// StderrWriter returns a tagged writer for the process's final line, using the
// same colour rules as everything else: a terminal, and NO_COLOR unset.
func StderrWriter() console.Writer {
	return console.Writer{
		W: os.Stderr,
		P: console.Painter{Enabled: isTerminal(os.Stderr) && !hasNoColorEnv()},
	}
}

func hasNoColorEnv() bool { return os.Getenv("NO_COLOR") != "" }

// isTerminal reports whether w is an interactive terminal, which decides
// whether output is coloured and whether progress redraws in place.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	// A redirect to /dev/null is a character device, so the mode check below
	// calls it a terminal and the scan then paints escape codes into it.
	if file.Name() == os.DevNull {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

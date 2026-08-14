// Command jenkins-bench audits a Jenkins controller against the Build Pipelines
// section of the CIS Software Supply Chain Security Guide.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/scm-bench/jenkins-bench/internal/cli"
	"github.com/scm-bench/jenkins-bench/internal/console"
)

func main() {
	// A scan can take a while on a controller with a lot of jobs — each one is
	// two requests — so Ctrl-C cancels the in-flight requests rather than
	// leaving the process to be killed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCommand()
	err := root.ExecuteContext(ctx)
	if err == nil {
		os.Exit(cli.ExitOK)
	}

	// The last line carries the same tag column as everything above it, so a
	// reader scanning down column one does not lose the thread at the one line
	// that says why the scan stopped.
	out := cli.StderrWriter()

	code := cli.ExitCode(err)
	switch {
	case errors.Is(err, context.Canceled):
		// Ctrl-C. Saying so beats exiting 2 in silence, which is
		// indistinguishable from a crash to anyone reading a log later.
		out.Line(console.Warn, "interrupted")
	case code == cli.ExitError:
		out.Line(console.Fail, "%v", err)
	default:
		// A findings exit is a successful scan with a negative result: the
		// report has already been printed, so only a one-line summary belongs
		// on stderr. INFO, not ERR — nothing went wrong with the scan.
		out.Line(console.Info, "%v", err)
	}
	os.Exit(code)
}

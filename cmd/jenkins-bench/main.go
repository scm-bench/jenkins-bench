// Command jenkins-bench audits a Jenkins controller against the Build Pipelines
// section of the CIS Software Supply Chain Security Guide.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/scm-bench/jenkins-bench/internal/cli"
)

// exit is os.Exit; a variable so the wiring below can be tested in-process.
var exit = os.Exit

func main() {
	// A scan can take a while on a controller with a lot of jobs — each one is
	// two requests — so Ctrl-C cancels the in-flight requests rather than
	// leaving the process to be killed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, cli.NewRootCommand(), cli.StderrWriter())
	stop()
	exit(code)
}

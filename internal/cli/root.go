// Package cli wires the command line to the fetcher, engine and reporters.
package cli

import (
	"github.com/spf13/cobra"
)

// Exit codes. They are part of the tool's contract with CI, so they are
// documented here rather than scattered as literals.
const (
	// ExitOK means the scan ran and nothing breached the --fail-on threshold.
	ExitOK = 0
	// ExitFindings means the scan ran and found failures at or above the
	// configured severity.
	ExitFindings = 1
	// ExitError means the scan itself could not complete.
	ExitError = 2
)

// NewRootCommand builds the command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "jenkins-bench",
		Short: "Audit a Jenkins controller against the CIS Software Supply Chain Security benchmark",
		Long: `jenkins-bench audits a Jenkins controller against the Build Pipelines section of
the CIS Software Supply Chain Security Guide.

It captures a read-only snapshot of the controller, evaluates it against policies
written in Rego, and reports what is misconfigured along with the exact settings
path to fix it. Controls the controller's API cannot answer are reported as
MANUAL rather than guessed at, and never affect the score — which on Jenkins is
not a formality: a least-privilege token cannot read a job's configuration, and
nothing about how a job is defined appears anywhere else.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newListChecksCommand())
	root.AddCommand(newVersionCommand())
	return root
}

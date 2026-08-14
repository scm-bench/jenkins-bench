package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "jenkins-bench %s\n", Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  commit: %s\n", Commit)
			fmt.Fprintf(cmd.OutOrStdout(), "  built:  %s\n", Date)
			fmt.Fprintf(cmd.OutOrStdout(), "  go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/scm-bench/jenkins-bench/internal/checks"
)

func newListChecksCommand() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "list-checks",
		Short: "List the controls in the policy bundle",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bundle, err := checks.Load()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(bundle.Checks)
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tSCOPE\tAUTOMATED\tTITLE")
			for _, c := range bundle.Checks {
				automated := "yes"
				if !c.Automated {
					automated = "no (manual)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					c.ID, strings.ToUpper(c.Severity), c.Scope, automated, c.Title)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(out, "\n%d controls\n", len(bundle.Checks))
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "print the full check metadata as JSON")
	return cmd
}

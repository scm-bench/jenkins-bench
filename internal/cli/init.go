package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scm-bench/jenkins-bench/examples"
	"github.com/scm-bench/jenkins-bench/internal/console"
)

func newInitCommand() *cobra.Command {
	var force bool
	var path string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a commented jenkins-bench.yaml into the working directory",
		Long: `Init writes a configuration file with every setting present, commented, and
set to its default. Nothing in it changes how a scan behaves until you edit it.

scan finds the file on its own — as jenkins-bench.yaml or .jenkins-bench.yaml in
the working directory, or config.yaml in the user config directory — so this is
usually the last time you need to name it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target := path
			if target == "" {
				wd, err := os.Getwd()
				if err != nil {
					return err
				}
				target = filepath.Join(wd, "jenkins-bench.yaml")
			}

			// Refusing by default rather than prompting: this command is as
			// likely to be run by a script as by a person, and overwriting a
			// tuned configuration is not something to do on a typo.
			if !force {
				if _, err := os.Stat(target); err == nil {
					return fmt.Errorf("%s already exists; pass --force to overwrite it", target)
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}

			if err := os.WriteFile(target, examples.ConfigYAML, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", target, err)
			}

			out := console.Writer{W: cmd.OutOrStdout()}
			out.Line(console.Info, "wrote %s", target)
			out.Line(console.Info, "every value is the default; scan picks the file up without --config")
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "where to write the file (default ./jenkins-bench.yaml)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}

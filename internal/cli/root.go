package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "ai-sec",
	Short:   "AI-Sec is an AI-assisted security scanner CLI",
	Version: Version,
}

func Execute() error {
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newIndexCmd())
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(newFindingsCmd())
	rootCmd.AddCommand(newShowCmd())
	rootCmd.AddCommand(newRemediateCmd())
	rootCmd.AddCommand(newDoctorCmd())
	rootCmd.AddCommand(newInstallToolsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(rootCmd.ErrOrStderr(), err.Error())
		return err
	}
	return nil
}

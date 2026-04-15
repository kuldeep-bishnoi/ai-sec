package cli

import (
	"ai-sec/internal/tools"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newInstallToolsCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "install-tools",
		Short: "Print or run commands to install missing tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := tools.CheckAll(cmd.Context(), tools.DefaultChecks())
			var missing []tools.ToolResult
			for _, r := range results {
				if r.Status == tools.StatusMissing {
					missing = append(missing, r)
				}
			}
			if len(missing) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "All tools present.")
				return nil
			}

			if runtime.GOOS == "linux" {
				fmt.Fprintln(cmd.OutOrStdout(), "Tip (Linux): from the repo root run ./scripts/install-linux.sh to install ai-sec and optional OSS scanners interactively.")
				fmt.Fprintln(cmd.OutOrStdout())
			}

			fmt.Fprintln(cmd.OutOrStdout(), "Missing tools detected. Suggested install commands:")
			for _, r := range missing {
				fmt.Fprintf(cmd.OutOrStdout(), "\n- %s:\n%s", r.Name, indent(r.Details, "  "))
			}

			if !yes {
				fmt.Fprintln(cmd.OutOrStdout(), "\nRe-run with --yes to attempt installation (requires interactive sudo when needed).")
				return nil
			}

			// Best-effort installer: we only automate syft/grype (Anchore installers). Others remain manual by default.
			// This avoids breaking system Python and respects distro differences.
			for _, r := range missing {
				switch r.Name {
				case "syft":
					if err := runShell(cmd, `curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin`); err != nil {
						return err
					}
				case "grype":
					if err := runShell(cmd, `curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin`); err != nil {
						return err
					}
				default:
					// Keep manual.
				}
			}

			fmt.Fprintln(cmd.OutOrStdout(), "Done. Run `ai-sec doctor` to verify.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Attempt installation (best-effort)")
	return cmd
}

func runShell(cmd *cobra.Command, s string) error {
	c := exec.CommandContext(cmd.Context(), "sh", "-lc", s)
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	c.Env = os.Environ()
	if err := c.Run(); err != nil {
		return fmt.Errorf("failed: %s: %w", strings.TrimSpace(s), err)
	}
	return nil
}

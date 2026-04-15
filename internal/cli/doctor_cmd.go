package cli

import (
	"ai-sec/internal/tools"
	"fmt"

	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check required external tools (SAST/SCA/secrets/LLM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := tools.CheckAll(cmd.Context(), tools.DefaultChecks())
			ok := true
			for _, r := range results {
				switch r.Status {
				case tools.StatusOK:
					fmt.Fprintf(cmd.OutOrStdout(), "OK      %-8s %s\n", r.Name, r.Details)
				case tools.StatusMissing:
					ok = false
					fmt.Fprintf(cmd.OutOrStdout(), "MISSING %-8s\n%s\n\n", r.Name, indent(r.Details, "  "))
				default:
					ok = false
					fmt.Fprintf(cmd.OutOrStdout(), "BROKEN  %-8s\n%s\n\n", r.Name, indent(r.Details, "  "))
				}
			}
			if !ok {
				return fmt.Errorf("one or more required tools are missing/broken")
			}
			return nil
		},
	}
	return cmd
}

func indent(s string, prefix string) string {
	out := ""
	for _, line := range splitLinesForIndent(s) {
		out += prefix + line + "\n"
	}
	return out
}

func splitLinesForIndent(s string) []string {
	var lines []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	lines = append(lines, cur)
	return lines
}

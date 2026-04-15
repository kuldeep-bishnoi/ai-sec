package cli

import (
	"ai-sec/internal/findings"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newShowCmd() *cobra.Command {
	var repoPath string
	cmd := &cobra.Command{
		Use:   "show <finding_id>",
		Short: "Show details for a finding from the last scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(repoPath)
			if err != nil {
				return err
			}
			rep, err := readLastReport(abs)
			if err != nil {
				return err
			}
			f, ok := findByID(rep.Findings, args[0])
			if !ok {
				return fmt.Errorf("finding id %q not found in last report", args[0])
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(f)
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "Repository path (default current directory)")
	return cmd
}

func findByID(fs []findings.Finding, id string) (findings.Finding, bool) {
	id = strings.TrimSpace(id)
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return findings.Finding{}, false
}

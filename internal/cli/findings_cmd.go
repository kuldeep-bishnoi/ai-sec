package cli

import (
	"ai-sec/internal/findings"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

func newFindingsCmd() *cobra.Command {
	var repoPath string
	var severity string
	var source string

	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List findings from the last scan (IDs for remediation)",
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(repoPath)
			if err != nil {
				return err
			}
			rep, err := readLastReport(abs)
			if err != nil {
				return err
			}

			fs := filterFindings(rep.Findings, severity, source)
			sort.Slice(fs, func(i, j int) bool {
				if fs[i].Severity != fs[j].Severity {
					return severityRank(fs[i].Severity) < severityRank(fs[j].Severity)
				}
				if fs[i].Source != fs[j].Source {
					return fs[i].Source < fs[j].Source
				}
				return fs[i].ID < fs[j].ID
			})

			for _, f := range fs {
				loc := f.PrimaryLocation.File
				if f.PrimaryLocation.StartLine > 0 {
					loc = fmt.Sprintf("%s:%d", loc, f.PrimaryLocation.StartLine)
				}
				short := strings.TrimSpace(f.Explanation)
				if len(short) > 80 {
					short = short[:80] + "…"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %-8s %-7s  %-40s  %s\n", f.ID, f.Severity, f.Source, loc, short)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&repoPath, "repo", ".", "Repository path (default current directory)")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severities (comma-separated, e.g. CRITICAL,HIGH)")
	cmd.Flags().StringVar(&source, "source", "", "Filter by sources (comma-separated, e.g. deps,secrets,sast,taint)")
	return cmd
}

func readLastReport(repoAbs string) (findings.Report, error) {
	b, err := os.ReadFile(filepath.Join(repoAbs, ".ai-sec", "last_report.json"))
	if err != nil {
		return findings.Report{}, fmt.Errorf("no last report found; run `ai-sec scan %s` first", repoAbs)
	}
	var rep findings.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return findings.Report{}, err
	}
	return rep, nil
}

func filterFindings(in []findings.Finding, severityCSV string, sourceCSV string) []findings.Finding {
	wantSev := map[string]bool{}
	for _, s := range splitCSV(severityCSV) {
		wantSev[strings.ToUpper(s)] = true
	}
	wantSrc := map[string]bool{}
	for _, s := range splitCSV(sourceCSV) {
		wantSrc[strings.ToLower(s)] = true
	}

	out := make([]findings.Finding, 0, len(in))
	for _, f := range in {
		if len(wantSev) > 0 && !wantSev[string(f.Severity)] {
			continue
		}
		if len(wantSrc) > 0 && !wantSrc[string(f.Source)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func severityRank(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 0
	case findings.SeverityHigh:
		return 1
	case findings.SeverityMedium:
		return 2
	case findings.SeverityLow:
		return 3
	case findings.SeverityInfo:
		return 4
	default:
		return 5
	}
}

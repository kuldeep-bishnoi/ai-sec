package report

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ai-sec/internal/findings"

	"golang.org/x/term"
)

type TextOptions struct {
	Limit int
	View  string // "full" or "compact"
}

func WriteText(w io.Writer, rep findings.Report) error {
	return WriteTextWithOptions(w, rep, TextOptions{Limit: 0, View: "full"})
}

func WriteTextWithOptions(w io.Writer, rep findings.Report, opts TextOptions) error {
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	useColor := isTerminal(w) && os.Getenv("NO_COLOR") == ""
	target := rep.TargetPath
	if target == "" {
		target = "."
	}

	writeBanner(bw, useColor)
	fmt.Fprintf(bw, "target: %s\n", target)
	fmt.Fprintf(bw, "time:   %s\n", rep.GeneratedAt.Format(timeFormat()))
	fmt.Fprintln(bw)

	findingsList := append([]findings.Finding(nil), rep.Findings...)
	sort.Slice(findingsList, func(i, j int) bool {
		if findingsList[i].Severity != findingsList[j].Severity {
			return severityRank(findingsList[i].Severity) < severityRank(findingsList[j].Severity)
		}
		if findings.NormalizePath(findingsList[i].PrimaryLocation.File) != findings.NormalizePath(findingsList[j].PrimaryLocation.File) {
			return findings.NormalizePath(findingsList[i].PrimaryLocation.File) < findings.NormalizePath(findingsList[j].PrimaryLocation.File)
		}
		return findingsList[i].PrimaryLocation.StartLine < findingsList[j].PrimaryLocation.StartLine
	})

	counts := countBySeverity(findingsList)
	fmt.Fprintf(bw, "findings: %d  (CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d, INFO %d)\n",
		len(findingsList),
		counts[findings.SeverityCritical],
		counts[findings.SeverityHigh],
		counts[findings.SeverityMedium],
		counts[findings.SeverityLow],
		counts[findings.SeverityInfo],
	)
	fmt.Fprintln(bw)

	// Dependency summary (SCA): group by package@version and count vulns per severity.
	if depSummary := buildDepSummary(findingsList); len(depSummary) > 0 {
		fmt.Fprintln(bw, "Dependencies (summary)")
		fmt.Fprintln(bw, "  package@version  vulns")
		for _, row := range depSummary {
			fmt.Fprintf(bw, "  %-30s %s\n", row.pkg, row.counts)
		}
		fmt.Fprintln(bw)
	}

	var current findings.Severity = ""
	limit := opts.Limit
	if limit < 0 {
		limit = 0
	}
	if opts.View == "compact" {
		// Compact view: one line per finding.
		for i, f := range findingsList {
			if limit > 0 && i >= limit {
				fmt.Fprintf(bw, "... %d more findings (use --limit 0 for all)\n", len(findingsList)-i)
				break
			}
			loc := formatLocation(rep.TargetPath, f.PrimaryLocation, true)
			fmt.Fprintf(bw, "%s %s %-7s %s  %s\n", severityBadge(f.Severity, useColor), f.ID, f.Source, loc, f.Type)
		}
		return nil
	}

	for i, f := range findingsList {
		if limit > 0 && i >= limit {
			fmt.Fprintf(bw, "... %d more findings (use --limit 0 for all)\n", len(findingsList)-i)
			break
		}
		if f.Severity != current {
			current = f.Severity
			fmt.Fprintf(bw, "%s\n", sectionHeader(string(current), useColor, current))
		}

		loc := formatLocation(rep.TargetPath, f.PrimaryLocation, true)
		title := fmt.Sprintf("%s  %s", loc, f.Type)
		fmt.Fprintf(bw, "%s %s\n", severityBadge(f.Severity, useColor), title)

		fmt.Fprintf(bw, "  %s     %s\n", detailKey("id:", useColor), detailVal(f.ID, useColor))
		fmt.Fprintf(bw, "  %s %s\n", detailKey("source:", useColor), detailVal(string(f.Source), useColor))
		if f.Confidence > 0 {
			fmt.Fprintf(bw, "  %s   %s\n", detailKey("conf:", useColor), detailVal(fmt.Sprintf("%.2f", f.Confidence), useColor))
		}

		if f.Explanation != "" {
			fmt.Fprintf(bw, "  %s\n", detailKey("reason:", useColor))
			for _, line := range wrapLines(f.Explanation, 78) {
				fmt.Fprintf(bw, "    %s\n", detailVal(line, useColor))
			}
		}
		if strings.TrimSpace(f.Evidence) != "" {
			fmt.Fprintf(bw, "  %s\n", detailKey("secret:", useColor))
			for _, line := range wrapLines(f.Evidence, 78) {
				fmt.Fprintf(bw, "    %s\n", detailVal(line, useColor))
			}
		}
		if f.Fix != "" {
			fmt.Fprintf(bw, "  %s\n", detailKey("fix:", useColor))
			for _, line := range wrapLines(f.Fix, 78) {
				fmt.Fprintf(bw, "    %s\n", detailVal(line, useColor))
			}
		}
		if f.Patch != nil && strings.TrimSpace(f.Patch.UnifiedDiff) != "" {
			fmt.Fprintf(bw, "  %s\n", detailKey("patch:", useColor))
			for _, line := range strings.Split(strings.TrimRight(f.Patch.UnifiedDiff, "\n"), "\n") {
				fmt.Fprintf(bw, "    %s\n", detailVal(line, useColor))
			}
		}
		if len(f.Trace) > 0 {
			fmt.Fprintf(bw, "  %s\n", detailKey("trace:", useColor))
			for _, step := range f.Trace {
				stepLoc := formatLocation(rep.TargetPath, step.Location, true)
				msg := strings.TrimSpace(step.Message)
				if msg == "" {
					fmt.Fprintf(bw, "    %s\n", detailVal("- "+stepLoc, useColor))
				} else {
					fmt.Fprintf(bw, "    %s\n", detailVal("- "+stepLoc+"  "+msg, useColor))
				}
			}
		}
		fmt.Fprintln(bw)
	}
	return nil
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

func timeFormat() string { return "2006-01-02 15:04:05Z07:00" }

func isTerminal(w io.Writer) bool {
	// Best-effort: common case is stdout/stderr.
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

func severityBadge(s findings.Severity, color bool) string {
	label := fmt.Sprintf("[%s]", s)
	if !color {
		return label
	}
	switch s {
	case findings.SeverityCritical:
		return ansi("1;97;41", label) // bright white on red
	case findings.SeverityHigh:
		return ansi("1;97;45", label) // bright white on magenta
	case findings.SeverityMedium:
		return ansi("1;30;43", label) // black on yellow
	case findings.SeverityLow:
		return ansi("1;30;46", label) // black on cyan
	case findings.SeverityInfo:
		return ansi("1;37;44", label) // white on blue
	default:
		return label
	}
}

func sectionHeader(title string, color bool, sev findings.Severity) string {
	h := "== " + title + " =="
	if !color {
		return h
	}
	switch sev {
	case findings.SeverityCritical:
		return ansi("1;31", h)
	case findings.SeverityHigh:
		return ansi("1;35", h)
	case findings.SeverityMedium:
		return ansi("1;33", h)
	case findings.SeverityLow:
		return ansi("1;36", h)
	case findings.SeverityInfo:
		return ansi("1;34", h)
	default:
		return ansi("1", h)
	}
}

func ansi(code string, s string) string {
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// detailKey colors a field label (e.g. "id:", "reason:"); detailVal keeps values bright white.
func detailKey(s string, color bool) string {
	if !color {
		return s
	}
	return ansi("1;36", s) // bold cyan
}

func detailVal(s string, color bool) string {
	if !color {
		return s
	}
	return ansi("97", s) // bright white
}

func writeBanner(w io.Writer, color bool) {
	// A simple fixed-width banner (avoids external deps like figlet).
	lines := []string{
		"    ___    ________                      __",
		"   /   |  /  _/ __/___ ___  ______ _____/ /",
		"  / /| |  / // /_/ __ `/ / / / __ `/ __  / ",
		" / ___ |_/ // __/ /_/ / /_/ / /_/ / /_/ /  ",
		"/_/  |_/___/_/  \\__,_/\\__,_/\\__,_/\\__,_/   ",
		"                 security scan",
	}
	if !color {
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
		return
	}
	// Bright cyan for the logo, dim for the subtitle.
	for i, l := range lines {
		if i == len(lines)-1 {
			fmt.Fprintln(w, ansi("2;37", l))
		} else {
			fmt.Fprintln(w, ansi("1;96", l))
		}
	}
}

func countBySeverity(fs []findings.Finding) map[findings.Severity]int {
	m := map[findings.Severity]int{
		findings.SeverityCritical: 0,
		findings.SeverityHigh:     0,
		findings.SeverityMedium:   0,
		findings.SeverityLow:      0,
		findings.SeverityInfo:     0,
	}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

func formatLocation(repoRoot string, loc findings.Location, relative bool) string {
	file := loc.File
	if relative && repoRoot != "" && file != "" {
		if rel, err := filepath.Rel(repoRoot, file); err == nil && !strings.HasPrefix(rel, "..") {
			file = filepath.ToSlash(rel)
		}
	}
	if loc.StartLine > 0 {
		return fmt.Sprintf("%s:%d", file, loc.StartLine)
	}
	return file
}

func wrapLines(s string, width int) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	paras := strings.Split(s, "\n")
	var out []string
	for _, p := range paras {
		p = strings.TrimSpace(p)
		if p == "" {
			out = append(out, "")
			continue
		}
		words := strings.Fields(p)
		var line strings.Builder
		for _, w := range words {
			if line.Len() == 0 {
				line.WriteString(w)
				continue
			}
			if line.Len()+1+len(w) > width {
				out = append(out, line.String())
				line.Reset()
				line.WriteString(w)
				continue
			}
			line.WriteByte(' ')
			line.WriteString(w)
		}
		if line.Len() > 0 {
			out = append(out, line.String())
		}
	}
	// Trim trailing blank lines
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

type depRow struct {
	pkg    string
	counts string
	total  int
	high   int
	med    int
	low    int
	crit   int
}

func buildDepSummary(fs []findings.Finding) []depRow {
	type agg struct {
		crit int
		high int
		med  int
		low  int
		info int
	}
	m := map[string]*agg{}
	for _, f := range fs {
		if f.Source != findings.EngineDeps {
			continue
		}
		// Our deps "location" uses dependency://<name> and the text includes name@version.
		key := strings.TrimPrefix(f.PrimaryLocation.File, "dependency://")
		if key == "" {
			key = f.PrimaryLocation.File
		}
		a := m[key]
		if a == nil {
			a = &agg{}
			m[key] = a
		}
		switch f.Severity {
		case findings.SeverityCritical:
			a.crit++
		case findings.SeverityHigh:
			a.high++
		case findings.SeverityMedium:
			a.med++
		case findings.SeverityLow:
			a.low++
		case findings.SeverityInfo:
			a.info++
		}
	}
	if len(m) == 0 {
		return nil
	}
	rows := make([]depRow, 0, len(m))
	for k, a := range m {
		total := a.crit + a.high + a.med + a.low + a.info
		counts := fmt.Sprintf("%d (C %d, H %d, M %d, L %d, I %d)", total, a.crit, a.high, a.med, a.low, a.info)
		rows = append(rows, depRow{
			pkg:    k,
			counts: counts,
			total:  total,
			crit:   a.crit,
			high:   a.high,
			med:    a.med,
			low:    a.low,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		// Sort by severity then total.
		if rows[i].crit != rows[j].crit {
			return rows[i].crit > rows[j].crit
		}
		if rows[i].high != rows[j].high {
			return rows[i].high > rows[j].high
		}
		if rows[i].med != rows[j].med {
			return rows[i].med > rows[j].med
		}
		if rows[i].total != rows[j].total {
			return rows[i].total > rows[j].total
		}
		return rows[i].pkg < rows[j].pkg
	})
	if len(rows) > 15 {
		rows = rows[:15]
	}
	return rows
}

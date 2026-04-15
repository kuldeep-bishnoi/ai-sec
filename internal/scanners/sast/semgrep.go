package sast

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/scanners/executil"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type semgrepJSON struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			// Fix is present when the rule defines fix / fix-regex (rule-defined replacement text).
			Fix      string `json:"fix"`
			Metadata struct {
				Impact string `json:"impact"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func ScanSemgrep(ctx context.Context, repoPath string) ([]findings.Finding, error) {
	res, err := executil.RunDir(ctx, repoPath, "semgrep",
		"scan",
		"--config", "auto",
		"--json",
		"--quiet",
		".",
	)
	if err != nil {
		// semgrep may exit non-zero when findings exist or when it hits parse errors.
		// If we got JSON on stdout, parse it anyway.
		var ee *exec.ExitError
		if !(errors.As(err, &ee) && len(res.Stdout) > 0) {
			return nil, err
		}
	}

	if len(res.Stdout) == 0 {
		return nil, nil
	}

	var sj semgrepJSON
	if err := json.Unmarshal(res.Stdout, &sj); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON: %w", err)
	}

	out := make([]findings.Finding, 0, len(sj.Results))
	for _, r := range sj.Results {
		loc := findings.Location{
			File:      findings.NormalizePath(r.Path),
			StartLine: r.Start.Line,
			EndLine:   r.End.Line,
		}
		typ := "SAST Finding"
		if r.CheckID != "" {
			typ = fmt.Sprintf("SAST: %s", r.CheckID)
		}

		sev := mapSemgrepSeverity(r.Extra.Severity)
		msg := strings.TrimSpace(r.Extra.Message)
		if msg == "" {
			msg = "Semgrep reported a potential security issue."
		}

		fix := strings.TrimSpace(r.Extra.Fix)
		if fix == "" {
			fix = "Review the finding and apply Semgrep’s recommended secure pattern for this issue."
		}

		f := findings.Finding{
			ID:              findings.StableID(findings.EngineSAST, typ, loc, r.CheckID),
			Type:            typ,
			Severity:        sev,
			Confidence:      0.7,
			PrimaryLocation: loc,
			Explanation:     msg,
			Impact:          strings.TrimSpace(r.Extra.Metadata.Impact),
			Fix:             fix,
			Source:          findings.EngineSAST,
			CreatedAt:       time.Now(),
		}
		out = append(out, f)
	}
	return out, nil
}

func mapSemgrepSeverity(s string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "high":
		return findings.SeverityHigh
	case "warning", "medium":
		return findings.SeverityMedium
	case "info", "low":
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

package secrets

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/scanners/executil"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type gitleaksFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
}

func ScanGitleaks(ctx context.Context, repoPath string, showSecrets bool) ([]findings.Finding, error) {
	// gitleaks exit code 1 indicates leaks found. We want consistent parsing across builds,
	// so always write the JSON report to a temp file and read it back.
	tmpDir, err := os.MkdirTemp("", "ai-sec-gitleaks-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	reportPath := filepath.Join(tmpDir, "gitleaks.json")

	_, runErr := executil.Run(ctx, "gitleaks",
		"detect",
		"--source", repoPath,
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-banner",
	)
	if runErr != nil {
		// Treat exit code 1 as success (leaks found). Anything else is a failure.
		var ee *exec.ExitError
		if !(errors.As(runErr, &ee) && ee.ExitCode() == 1) {
			return nil, runErr
		}
	}

	b, err := os.ReadFile(reportPath)
	if err != nil {
		// If no report exists, treat as no findings.
		return nil, nil
	}
	if len(b) == 0 {
		return nil, nil
	}

	var raw []gitleaksFinding
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON: %w", err)
	}

	out := make([]findings.Finding, 0, len(raw))
	for _, r := range raw {
		loc := findings.Location{
			File:      findings.NormalizePath(r.File),
			StartLine: r.StartLine,
			EndLine:   r.EndLine,
		}

		typ := "Hardcoded Secret"
		if r.RuleID != "" {
			typ = fmt.Sprintf("Secret: %s", r.RuleID)
		}

		expl := r.Description
		if expl == "" {
			expl = "A secret-like value was detected by gitleaks."
		}

		// Conservative default: treat secrets as HIGH unless clearly a private key.
		sev := findings.SeverityHigh
		ruleLower := strings.ToLower(r.RuleID)
		descLower := strings.ToLower(r.Description)
		if strings.Contains(ruleLower, "private") || strings.Contains(descLower, "private key") || strings.Contains(descLower, "rsa") {
			sev = findings.SeverityCritical
		}

		f := findings.Finding{
			ID:              findings.StableID(findings.EngineSecrets, typ, loc, r.RuleID),
			Type:            typ,
			Severity:        sev,
			Confidence:      0.9,
			PrimaryLocation: loc,
			Explanation:     expl,
			Evidence:        secretEvidence(r, showSecrets),
			Fix:             "Remove the secret from the repository, rotate it immediately, and replace with a secure secret manager or environment-based configuration.",
			Source:          findings.EngineSecrets,
			CreatedAt:       time.Now(),
		}
		out = append(out, f)
	}
	return out, nil
}

func secretEvidence(r gitleaksFinding, show bool) string {
	if !show {
		return ""
	}
	// Prefer Match (often shorter). Fall back to Secret.
	s := strings.TrimSpace(r.Match)
	if s == "" {
		s = strings.TrimSpace(r.Secret)
	}
	if s == "" {
		return ""
	}
	// Avoid dumping huge blobs.
	const max = 120
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

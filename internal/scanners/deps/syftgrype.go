package deps

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/scanners/executil"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type grypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}

type grypeJSON struct {
	Matches []grypeMatch `json:"matches"`
}

func ScanSyftGrype(ctx context.Context, repoPath string) ([]findings.Finding, error) {
	tmpDir, err := os.MkdirTemp("", "ai-sec-sbom-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	sbomPath := filepath.Join(tmpDir, "sbom.json")

	// Create SBOM via syft (CycloneDX JSON is a stable choice).
	if _, err := executil.Run(ctx, "syft", repoPath, "-o", "cyclonedx-json="+sbomPath); err != nil {
		return nil, err
	}

	res, err := executil.Run(ctx, "grype", "sbom:"+sbomPath, "-o", "json")
	if err != nil {
		return nil, err
	}

	var gj grypeJSON
	if err := json.Unmarshal(res.Stdout, &gj); err != nil {
		return nil, fmt.Errorf("failed to parse grype JSON: %w", err)
	}

	out := make([]findings.Finding, 0, len(gj.Matches))
	for _, m := range gj.Matches {
		vID := m.Vulnerability.ID
		if vID == "" {
			continue
		}

		sev := mapGrypeSeverity(m.Vulnerability.Severity)
		typ := fmt.Sprintf("Vulnerable Dependency: %s", vID)

		expl := fmt.Sprintf("Dependency vulnerability reported by grype: %s %s@%s (%s).",
			vID, m.Artifact.Name, m.Artifact.Version, m.Artifact.Type,
		)

		loc := findings.Location{File: findings.NormalizePath("dependency://" + m.Artifact.Name)}
		f := findings.Finding{
			ID:              findings.StableID(findings.EngineDeps, typ, loc, vID+"|"+m.Artifact.Version),
			Type:            typ,
			Severity:        sev,
			Confidence:      0.85,
			PrimaryLocation: loc,
			Explanation:     expl,
			Fix:             "Upgrade the affected dependency to a non-vulnerable version (or apply vendor patch/backport) and rebuild/redeploy.",
			Source:          findings.EngineDeps,
			CreatedAt:       time.Now(),
		}
		out = append(out, f)
	}
	return out, nil
}

func mapGrypeSeverity(s string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

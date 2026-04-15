package deps

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/scanners/executil"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ScanCdxgenGrype generates a CycloneDX SBOM via cdxgen, then scans it via grype.
// This is useful when syft is unavailable or when you prefer cdxgen for SBOM generation.
func ScanCdxgenGrype(ctx context.Context, repoPath string) ([]findings.Finding, error) {
	tmpDir, err := os.MkdirTemp("", "ai-sec-cdx-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	sbomPath := filepath.Join(tmpDir, "sbom.cdx.json")

	// cdxgen writes to a file.
	if _, err := executil.Run(ctx, "cdxgen", "-o", sbomPath, repoPath); err != nil {
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
		expl := fmt.Sprintf("Dependency vulnerability reported by grype (SBOM via cdxgen): %s %s@%s (%s).",
			vID, m.Artifact.Name, m.Artifact.Version, m.Artifact.Type,
		)
		loc := findings.Location{File: findings.NormalizePath("dependency://" + m.Artifact.Name)}
		out = append(out, findings.Finding{
			ID:              findings.StableID(findings.EngineDeps, typ, loc, vID+"|"+m.Artifact.Version),
			Type:            typ,
			Severity:        sev,
			Confidence:      0.85,
			PrimaryLocation: loc,
			Explanation:     expl,
			Fix:             "Upgrade the affected dependency to a non-vulnerable version (or apply vendor patch/backport) and rebuild/redeploy.",
			Source:          findings.EngineDeps,
			CreatedAt:       time.Now(),
		})
	}
	return out, nil
}

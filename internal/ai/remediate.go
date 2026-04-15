package ai

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/rag"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Remediation struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Confidence  any    `json:"confidence"`
	Explanation string `json:"explanation"`
	Impact      string `json:"impact"`
	FixPlan     string `json:"fix_plan"`
	Patch       string `json:"patch"`
}

type GenerateOptions struct {
	DebugRaw bool
	Logf     func(format string, args ...any)
}

func GenerateRemediation(ctx context.Context, p Provider, f findings.Finding, chunks []rag.Chunk) (findings.Finding, error) {
	return GenerateRemediationWithOptions(ctx, p, f, chunks, GenerateOptions{})
}

func GenerateRemediationWithOptions(ctx context.Context, p Provider, f findings.Finding, chunks []rag.Chunk, opts GenerateOptions) (findings.Finding, error) {
	prompt := buildPrompt(f, chunks)
	raw, err := p.Generate(ctx, prompt)
	if err != nil {
		return findings.Finding{}, err
	}
	if opts.DebugRaw && opts.Logf != nil {
		opts.Logf("llm_raw_response:\n%s\n", raw)
	}

	// Attempt to extract JSON if the model wraps it in text.
	raw = strings.TrimSpace(raw)
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		raw = raw[start : end+1]
	}

	var r Remediation
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return findings.Finding{}, fmt.Errorf("failed to parse AI JSON: %w", err)
	}

	loc := f.PrimaryLocation
	typ := r.Type
	if typ == "" {
		typ = f.Type
	}

	conf := coerceConfidence(r.Confidence)
	aiFinding := findings.Finding{
		ID:              findings.StableID(findings.EngineAI, typ, loc, f.ID),
		Type:            typ,
		Severity:        f.Severity,
		Confidence:      conf,
		PrimaryLocation: loc,
		Trace:           f.Trace,
		Explanation:     strings.TrimSpace(r.Explanation),
		Impact:          strings.TrimSpace(r.Impact),
		Fix:             strings.TrimSpace(r.FixPlan),
		Source:          findings.EngineAI,
		CreatedAt:       time.Now(),
	}
	if strings.TrimSpace(r.Patch) != "" {
		aiFinding.Patch = &findings.Patch{UnifiedDiff: strings.TrimSpace(r.Patch)}
	}
	if aiFinding.Confidence == 0 {
		aiFinding.Confidence = 0.5
	}
	return aiFinding, nil
}

func coerceConfidence(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
	case string:
		x = strings.TrimSpace(x)
		if x == "" {
			return 0
		}
		// Allow "0.7" style strings.
		if f, err := json.Number(x).Float64(); err == nil {
			return f
		}
	}
	return 0
}

func buildPrompt(f findings.Finding, chunks []rag.Chunk) string {
	var b strings.Builder
	b.WriteString("You are a senior security engineer.\n")
	b.WriteString("You MUST return ONLY a single JSON object with keys: type, severity, confidence, explanation, impact, fix_plan, patch.\n")
	b.WriteString("Constraints (STRICT):\n")
	b.WriteString("- Preserve behavior: do not refactor, rename, or restructure.\n")
	b.WriteString("- Make the smallest possible change to mitigate the issue.\n")
	b.WriteString("- Only modify the file(s) implicated by the finding (location/trace) unless absolutely required.\n")
	b.WriteString("- If you can produce a safe code fix, patch MUST be a valid unified diff (git-style with ---/+++ and @@ hunks).\n")
	b.WriteString("- If no safe patch exists, set patch to an empty string and explain why in fix_plan.\n\n")

	b.WriteString("Finding:\n")
	b.WriteString(fmt.Sprintf("type: %s\nseverity: %s\nfile: %s:%d\n", f.Type, f.Severity, f.PrimaryLocation.File, f.PrimaryLocation.StartLine))
	if f.Explanation != "" {
		b.WriteString("scanner_reason:\n" + f.Explanation + "\n")
	}
	if len(f.Trace) > 0 {
		b.WriteString("\ntrace:\n")
		for _, t := range f.Trace {
			loc := t.Location.File
			if t.Location.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", loc, t.Location.StartLine)
			}
			b.WriteString(fmt.Sprintf("- %s: %s\n", loc, t.Message))
		}
	}
	b.WriteString("\nPatch output rules:\n")
	b.WriteString("- patch MUST apply cleanly to the shown code.\n")
	b.WriteString("- patch MUST be minimal: touch as few lines as possible.\n")
	b.WriteString("- Do NOT include markdown fences.\n\n")

	b.WriteString("\nrelevant_repo_context:\n")
	for i, c := range chunks {
		b.WriteString(fmt.Sprintf("\n[chunk_%d] file=%s lines=%d-%d lang=%s\n", i+1, c.File, c.StartLine, c.EndLine, c.Language))
		b.WriteString(c.Text)
		b.WriteString("\n")
	}

	return b.String()
}

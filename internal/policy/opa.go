package policy

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/scanners/executil"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Decision struct {
	Deny []string `json:"deny"`
}

// EvaluateOPA runs `opa eval` against a rego policy file. The policy should expose `data.<pkg>.deny`
// as an array of strings. We evaluate `data.deny` by default for simplicity.
func EvaluateOPA(ctx context.Context, repoRoot string, regoPath string, rep findings.Report) (Decision, error) {
	absPolicy, err := filepath.Abs(regoPath)
	if err != nil {
		return Decision{}, err
	}
	if _, err := os.Stat(absPolicy); err != nil {
		return Decision{}, err
	}

	inputBytes, err := rep.MarshalJSON()
	if err != nil {
		return Decision{}, err
	}

	tmpDir, err := os.MkdirTemp("", "ai-sec-opa-*")
	if err != nil {
		return Decision{}, err
	}
	defer os.RemoveAll(tmpDir)

	inputPath := filepath.Join(tmpDir, "input.json")
	if err := os.WriteFile(inputPath, inputBytes, 0o644); err != nil {
		return Decision{}, err
	}

	// Query `data.deny` (policy can set deny at the root package).
	res, err := executil.Run(ctx, "opa",
		"eval",
		"--format", "json",
		"--data", absPolicy,
		"--input", inputPath,
		"data.deny",
	)
	if err != nil {
		return Decision{}, fmt.Errorf("opa eval failed: %w", err)
	}

	// Parse OPA JSON output.
	var raw struct {
		Result []struct {
			Expressions []struct {
				Value any `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.Stdout, &raw); err != nil {
		return Decision{}, fmt.Errorf("parse opa output: %w", err)
	}

	dec := Decision{}
	for _, r := range raw.Result {
		for _, e := range r.Expressions {
			// Expect value to be []any (array of strings).
			if arr, ok := e.Value.([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						dec.Deny = append(dec.Deny, s)
					}
				}
			}
		}
	}
	_ = repoRoot
	return dec, nil
}

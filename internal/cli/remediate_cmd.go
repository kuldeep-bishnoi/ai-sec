package cli

import (
	"ai-sec/internal/ai"
	"ai-sec/internal/findings"
	"ai-sec/internal/patch"
	"ai-sec/internal/rag"
	"ai-sec/internal/remediate"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func newRemediateCmd() *cobra.Command {
	var repoPath string
	var llm string
	var ollamaURL string
	var ollamaModel string
	var ollamaTimeoutSec int
	var geminiModel string
	var geminiTimeoutSec int
	var strict bool
	var apply bool
	var debugLLM bool
	var checkCmd string

	cmd := &cobra.Command{
		Use:   "remediate <finding_id>",
		Short: "Generate a strict, behavior-preserving remediation patch",
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

			// For secrets/deps we provide guidance; strict auto-patching is risky.
			if f.Source == findings.EngineSecrets {
				fmt.Fprintln(cmd.OutOrStdout(), "Secrets remediation (strict, behavior-preserving):")
				fmt.Fprintln(cmd.OutOrStdout(), "- Rotate/revoke the credential immediately")
				fmt.Fprintln(cmd.OutOrStdout(), "- Remove the secret from the repo (and rewrite history if required)")
				fmt.Fprintln(cmd.OutOrStdout(), "- Replace with secret manager / environment injection")
				fmt.Fprintln(cmd.OutOrStdout(), "- Re-run scan to confirm removal")
				return nil
			}
			if f.Source == findings.EngineDeps {
				fmt.Fprintln(cmd.OutOrStdout(), "Dependency remediation (strict, behavior-preserving):")
				fmt.Fprintln(cmd.OutOrStdout(), "- Upgrade the affected package to a non-vulnerable version (smallest bump)")
				fmt.Fprintln(cmd.OutOrStdout(), "- Regenerate lockfile if used")
				fmt.Fprintln(cmd.OutOrStdout(), "- Rebuild and rerun tests/lint")
				return nil
			}

			if llm == "" {
				llm = "ollama"
			}
			if llm == "off" {
				return fmt.Errorf("LLM disabled; remediation patch generation requires --llm ollama|gemini")
			}

			pp := ai.ProviderParams{
				Mode:          llm,
				OllamaURL:     ollamaURL,
				OllamaModel:   ollamaModel,
				OllamaTimeout: time.Duration(ollamaTimeoutSec) * time.Second,
				GeminiModel:   geminiModel,
				GeminiTimeout: time.Duration(geminiTimeoutSec) * time.Second,
			}
			provider, err := ai.NewProvider(pp)
			if err != nil {
				return err
			}

			query := fmt.Sprintf("%s %s %s", f.Type, f.PrimaryLocation.File, f.Explanation)
			rr, err := rag.Retrieve(cmd.Context(), abs, query, 8)
			if err != nil {
				// Fallback: build chunks in-memory when index is missing.
				chunks, cErr := rag.ChunkRepository(abs, rag.DefaultChunkOptions())
				if cErr != nil {
					return err
				}
				rr = rag.RetrieveFromChunks(cmd.Context(), chunks, query, 8)
			}

			aiF, err := ai.GenerateRemediationWithOptions(cmd.Context(), provider, f, rr.Chunks, ai.GenerateOptions{
				DebugRaw: debugLLM,
				Logf: func(format string, args ...any) {
					fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
				},
			})
			if err != nil {
				return err
			}

			// Strict enforcement: for code findings, require a patch unless the model explicitly couldn't.
			if strict && (f.Source == findings.EngineTaint || f.Source == findings.EngineSAST) {
				if aiF.Patch == nil || aiF.Patch.UnifiedDiff == "" {
					return fmt.Errorf("strict remediation produced no patch; refusing to proceed")
				}
			}

			// Show plan + patch preview in JSON for now (easy to consume programmatically).
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(aiF)

			if !apply {
				return nil
			}
			if !strict {
				return fmt.Errorf("refusing to apply without --strict")
			}
			if aiF.Patch == nil || aiF.Patch.UnifiedDiff == "" {
				return fmt.Errorf("no patch produced")
			}

			touched, err := remediate.TouchedFilesFromDiff(aiF.Patch.UnifiedDiff)
			if err != nil {
				return err
			}

			// Apply patch.
			if _, err := patch.ApplyUnifiedDiff(abs, aiF.Patch.UnifiedDiff); err != nil {
				return err
			}

			// Run strict validations (lint/compile/tests best-effort). Fail closed.
			if _, err := remediate.ValidateStrict(cmd.Context(), abs, touched, checkCmd); err != nil {
				return err
			}

			// Persist last remediation.
			_ = os.WriteFile(filepath.Join(abs, ".ai-sec", "last_remediation.json"), mustJSON(aiF), 0o644)
			fmt.Fprintln(cmd.OutOrStdout(), "applied: strict checks passed")
			return nil
		},
	}

	cmd.Flags().StringVar(&repoPath, "repo", ".", "Repository path (default current directory)")
	cmd.Flags().StringVar(&llm, "llm", "ollama", "LLM backend: ollama|gemini|off (gemini uses GOOGLE_API_KEY or GEMINI_API_KEY)")
	cmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama base URL (default http://localhost:11434)")
	cmd.Flags().StringVar(&ollamaModel, "ollama-model", "", "Ollama model to use (e.g. novaforgeai/deepseek-coder:6.7b-optimized)")
	cmd.Flags().IntVar(&ollamaTimeoutSec, "ollama-timeout", 180, "Ollama request timeout in seconds")
	cmd.Flags().StringVar(&geminiModel, "gemini-model", "", "Gemini model id (default gemini-2.0-flash; e.g. gemini-flash-latest)")
	cmd.Flags().IntVar(&geminiTimeoutSec, "gemini-timeout", 600, "Gemini request timeout in seconds")
	cmd.Flags().BoolVar(&strict, "strict", true, "Strict mode (no behavior change; fail closed)")
	cmd.Flags().BoolVar(&apply, "apply", false, "Apply patch if strict checks pass")
	cmd.Flags().BoolVar(&debugLLM, "debug-llm", false, "Print raw LLM response to stderr (may contain sensitive data)")
	cmd.Flags().StringVar(&checkCmd, "check-cmd", "", "Custom strict validation command (e.g. \"make lint && make test\")")
	return cmd
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

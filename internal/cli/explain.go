package cli

import (
	"ai-sec/internal/ai"
	"ai-sec/internal/findings"
	"ai-sec/internal/rag"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	var repoPath string
	var llm string
	cmd := &cobra.Command{
		Use:   "explain <finding_id>",
		Short: "Explain a prior finding with additional context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(cmd, repoPath, llm, args[0])
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "Repository path (default current directory)")
	cmd.Flags().StringVar(&llm, "llm", "ollama", "LLM backend: ollama|gemini|off")
	return cmd
}

func runExplain(cmd *cobra.Command, repoPath string, llm string, findingID string) error {
	if repoPath == "" {
		repoPath = "."
	}
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(abs, ".ai-sec", "last_report.json"))
	if err != nil {
		return fmt.Errorf("no last report found; run `ai-sec scan %s` first", abs)
	}
	var rep findings.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return err
	}

	var f *findings.Finding
	for i := range rep.Findings {
		if rep.Findings[i].ID == findingID {
			f = &rep.Findings[i]
			break
		}
	}
	if f == nil {
		return fmt.Errorf("finding id %q not found in last report", findingID)
	}

	if llm == "" {
		llm = "ollama"
	}
	if llm == "off" {
		// Just print the raw finding.
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(f)
		return nil
	}

	pp := ai.ProviderParams{Mode: llm}
	provider, err := ai.NewProvider(pp)
	if err != nil {
		return err
	}

	query := fmt.Sprintf("%s %s %s", f.Type, f.PrimaryLocation.File, f.Explanation)
	rr, err := rag.Retrieve(cmd.Context(), abs, query, 6)
	if err != nil {
		// Same fallback as remediate: in-memory chunks when index is missing.
		chunks, cErr := rag.ChunkRepository(abs, rag.DefaultChunkOptions())
		if cErr != nil {
			return err
		}
		rr = rag.RetrieveFromChunks(cmd.Context(), chunks, query, 6)
	}
	aiF, err := ai.GenerateRemediation(cmd.Context(), provider, *f, rr.Chunks)
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(aiF)
}

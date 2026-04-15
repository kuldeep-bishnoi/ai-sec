package cli

import (
	"ai-sec/internal/rag"
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newIndexCmd() *cobra.Command {
	var useEmb bool
	var ollamaURL string
	var ollamaModel string

	cmd := &cobra.Command{
		Use:   "index <path>",
		Short: "Build or update the repository RAG index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIndex(cmd.Context(), cmd, args[0], useEmb, ollamaURL, ollamaModel)
		},
	}
	cmd.Flags().BoolVar(&useEmb, "embeddings", true, "Compute embeddings (Ollama) when available")
	cmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama base URL (default http://localhost:11434)")
	cmd.Flags().StringVar(&ollamaModel, "ollama-embed-model", "", "Ollama embedding model (default nomic-embed-text)")
	return cmd
}

func runIndex(ctx context.Context, cmd *cobra.Command, target string, useEmb bool, ollamaURL string, ollamaModel string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}

	opts := rag.DefaultIndexOptions()
	opts.UseEmbeddings = useEmb
	if ollamaURL != "" {
		opts.Ollama.BaseURL = ollamaURL
	}
	if ollamaModel != "" {
		opts.Ollama.Model = ollamaModel
	}

	meta, err := rag.BuildIndex(ctx, abs, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "index built: %s/.ai-sec/index.jsonl\n", abs)
	fmt.Fprintf(cmd.OutOrStdout(), "embeddings: %v (%s %s)\n", meta.HasEmbeddings, meta.EmbeddingProvider, meta.EmbeddingModel)
	return nil
}

package rag

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

type IndexOptions struct {
	ChunkOptions  ChunkOptions
	UseEmbeddings bool
	Ollama        OllamaClient
}

func DefaultIndexOptions() IndexOptions {
	return IndexOptions{
		ChunkOptions:  DefaultChunkOptions(),
		UseEmbeddings: true,
		Ollama:        DefaultOllamaClient(),
	}
}

func BuildIndex(ctx context.Context, repoPath string, opts IndexOptions) (IndexMeta, error) {
	chunks, err := ChunkRepository(repoPath, opts.ChunkOptions)
	if err != nil {
		return IndexMeta{}, err
	}

	indexDir := filepath.Join(repoPath, ".ai-sec")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		return IndexMeta{}, err
	}

	indexPath := filepath.Join(indexDir, "index.jsonl")
	metaPath := filepath.Join(indexDir, "meta.json")

	meta := IndexMeta{
		EmbeddingProvider: "none",
		EmbeddingModel:    "",
		HasEmbeddings:     false,
	}

	if opts.UseEmbeddings {
		meta.EmbeddingProvider = "ollama"
		meta.EmbeddingModel = opts.Ollama.Model
	}

	f, err := os.Create(indexPath)
	if err != nil {
		return IndexMeta{}, err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for i := range chunks {
		if opts.UseEmbeddings {
			emb, err := opts.Ollama.Embed(ctx, chunks[i].Text)
			if err == nil {
				chunks[i].Embedding = emb
				meta.HasEmbeddings = true
			}
		}
		b, _ := json.Marshal(chunks[i])
		if _, err := w.Write(append(b, '\n')); err != nil {
			return IndexMeta{}, err
		}
	}

	if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(metaPath, append(b, '\n'), 0o644)
	}
	return meta, nil
}

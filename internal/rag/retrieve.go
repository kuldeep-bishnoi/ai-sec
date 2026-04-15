package rag

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type RetrieveResult struct {
	Chunks []Chunk
}

func Retrieve(ctx context.Context, repoPath string, query string, k int) (RetrieveResult, error) {
	if k <= 0 {
		k = 5
	}
	indexPath := filepath.Join(repoPath, ".ai-sec", "index.jsonl")
	f, err := os.Open(indexPath)
	if err != nil {
		return RetrieveResult{}, err
	}
	defer f.Close()

	var all []Chunk
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c Chunk
		if err := json.Unmarshal(sc.Bytes(), &c); err == nil {
			all = append(all, c)
		}
	}
	return RetrieveFromChunks(ctx, all, query, k), nil
}

func RetrieveFromChunks(ctx context.Context, chunks []Chunk, query string, k int) RetrieveResult {
	if k <= 0 {
		k = 5
	}

	// Prefer embeddings if present; otherwise fallback to lexical similarity.
	hasEmb := false
	for _, c := range chunks {
		if len(c.Embedding) > 0 {
			hasEmb = true
			break
		}
	}

	type scored struct {
		c     Chunk
		score float64
	}
	var scoredChunks []scored

	if hasEmb {
		// Embedding query requires ollama; if unavailable, fallback.
		oc := DefaultOllamaClient()
		emb, err := oc.Embed(ctx, query)
		if err == nil {
			for _, c := range chunks {
				if len(c.Embedding) == 0 || len(c.Embedding) != len(emb) {
					continue
				}
				scoredChunks = append(scoredChunks, scored{c: c, score: cosine(c.Embedding, emb)})
			}
		}
	}

	if len(scoredChunks) == 0 {
		qTokens := tokenize(query)
		for _, c := range chunks {
			score := bm25Like(tokenize(c.Text), qTokens)
			scoredChunks = append(scoredChunks, scored{c: c, score: score})
		}
	}

	sort.Slice(scoredChunks, func(i, j int) bool { return scoredChunks[i].score > scoredChunks[j].score })
	if len(scoredChunks) > k {
		scoredChunks = scoredChunks[:k]
	}

	out := make([]Chunk, 0, len(scoredChunks))
	for _, s := range scoredChunks {
		out = append(out, s.c)
	}
	return RetrieveResult{Chunks: out}
}

func cosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func tokenize(s string) []string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("(", " ", ")", " ", "{", " ", "}", " ", "[", " ", "]", " ", ".", " ", ",", " ", ";", " ", ":", " ", "\"", " ", "'", " ").Replace(s)
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) < 2 {
			continue
		}
		out = append(out, p)
	}
	return out
}

func bm25Like(docTokens, queryTokens []string) float64 {
	if len(queryTokens) == 0 {
		return 0
	}
	doc := make(map[string]int, len(docTokens))
	for _, t := range docTokens {
		doc[t]++
	}
	var score float64
	for _, qt := range queryTokens {
		tf := float64(doc[qt])
		if tf == 0 {
			continue
		}
		// Lightweight heuristic (not true BM25 without corpus stats).
		score += math.Log(1+tf) * 1.2
	}
	return score
}

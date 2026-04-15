package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OllamaClient struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

func DefaultOllamaClient() OllamaClient {
	return OllamaClient{
		BaseURL: "http://localhost:11434",
		Model:   "nomic-embed-text",
		Timeout: 30 * time.Second,
	}
}

func (c OllamaClient) Embed(ctx context.Context, text string) ([]float32, error) {
	type req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	type resp struct {
		Embedding []float32 `json:"embedding"`
	}

	body, _ := json.Marshal(req{Model: c.Model, Prompt: text})
	httpClient := &http.Client{Timeout: c.Timeout}
	u := fmt.Sprintf("%s/api/embeddings", c.BaseURL)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")

	res, err := httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("ollama embeddings HTTP %d", res.StatusCode)
	}

	var out resp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Embedding) == 0 {
		return nil, fmt.Errorf("ollama returned empty embedding")
	}
	return out.Embedding, nil
}

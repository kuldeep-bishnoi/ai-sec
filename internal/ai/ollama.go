package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OllamaProvider struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

func DefaultOllamaProvider() OllamaProvider {
	return OllamaProvider{
		BaseURL: "http://localhost:11434",
		// Leave as a reasonable default, but callers should override to an installed model.
		Model:   "novaforgeai/deepseek-coder:6.7b-optimized",
		Timeout: 60 * time.Minute,
	}
}

func (p OllamaProvider) Name() string { return "ollama" }

func (p OllamaProvider) Generate(ctx context.Context, prompt string) (string, error) {
	type req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream bool   `json:"stream"`
	}
	type resp struct {
		Response string `json:"response"`
	}

	body, _ := json.Marshal(req{Model: p.Model, Prompt: prompt, Stream: false})
	httpClient := &http.Client{Timeout: p.Timeout}
	u := fmt.Sprintf("%s/api/generate", p.BaseURL)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(r)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		msg := string(bytes.TrimSpace(b))
		if msg != "" {
			return "", fmt.Errorf("ollama generate HTTP %d: %s", res.StatusCode, msg)
		}
		return "", fmt.Errorf("ollama generate HTTP %d", res.StatusCode)
	}
	var out resp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Response == "" {
		return "", fmt.Errorf("ollama returned empty response")
	}
	return out.Response, nil
}

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// GeminiProvider calls Google Generative Language API (Gemini).
// API key: set GOOGLE_API_KEY or GEMINI_API_KEY (never commit keys).
type GeminiProvider struct {
	APIKey   string
	Model    string
	BaseURL  string
	Timeout  time.Duration
	JSONMode bool // request JSON output via generationConfig.responseMimeType
}

func DefaultGeminiProvider() GeminiProvider {
	key := strings.TrimSpace(os.Getenv("GOOGLE_API_KEY"))
	if key == "" {
		key = strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	}
	return GeminiProvider{
		APIKey:   key,
		Model:    "gemini-2.0-flash",
		BaseURL:  "https://generativelanguage.googleapis.com",
		Timeout:  10 * time.Minute,
		JSONMode: true,
	}
}

func (p GeminiProvider) Name() string { return "gemini" }

func (p GeminiProvider) Generate(ctx context.Context, prompt string) (string, error) {
	if strings.TrimSpace(p.APIKey) == "" {
		return "", fmt.Errorf("gemini: set GOOGLE_API_KEY or GEMINI_API_KEY in the environment")
	}
	model := strings.TrimSpace(p.Model)
	if model == "" {
		model = "gemini-2.0-flash"
	}
	base := strings.TrimSuffix(strings.TrimSpace(p.BaseURL), "/")
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}
	u := fmt.Sprintf("%s/v1beta/models/%s:generateContent", base, url.PathEscape(model))

	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Parts []part `json:"parts"`
	}
	type genCfg struct {
		ResponseMimeType string `json:"responseMimeType,omitempty"`
	}
	type reqBody struct {
		Contents         []content `json:"contents"`
		GenerationConfig *genCfg   `json:"generationConfig,omitempty"`
	}
	body := reqBody{
		Contents: []content{{Parts: []part{{Text: prompt}}}},
	}
	if p.JSONMode {
		body.GenerationConfig = &genCfg{ResponseMimeType: "application/json"}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	httpClient := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-goog-api-key", p.APIKey)

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if msg != "" {
			return "", fmt.Errorf("gemini generate HTTP %d: %s", res.StatusCode, truncateForErr(msg, 2048))
		}
		return "", fmt.Errorf("gemini generate HTTP %d", res.StatusCode)
	}

	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		PromptFeedback *struct {
			BlockReason string `json:"blockReason"`
		} `json:"promptFeedback"`
		Error *struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("gemini: decode response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("gemini API error: %s", out.Error.Message)
	}
	if out.PromptFeedback != nil && out.PromptFeedback.BlockReason != "" {
		return "", fmt.Errorf("gemini blocked prompt: %s", out.PromptFeedback.BlockReason)
	}
	if len(out.Candidates) == 0 {
		return "", fmt.Errorf("gemini returned no candidates (empty response)")
	}
	var sb strings.Builder
	for _, c := range out.Candidates {
		for _, pt := range c.Content.Parts {
			sb.WriteString(pt.Text)
		}
	}
	s := strings.TrimSpace(sb.String())
	if s == "" {
		return "", fmt.Errorf("gemini returned empty text")
	}
	return s, nil
}

func truncateForErr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

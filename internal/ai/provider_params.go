package ai

import (
	"fmt"
	"time"
)

// ProviderParams configures which backend to use from CLI flags.
type ProviderParams struct {
	Mode string // ollama|gemini|google|hosted|off

	OllamaURL      string
	OllamaModel    string
	OllamaTimeout time.Duration
	GeminiModel   string
	GeminiTimeout time.Duration
}

// NewProvider returns a concrete Provider for the given mode.
func NewProvider(p ProviderParams) (Provider, error) {
	switch p.Mode {
	case "", "ollama":
		out := DefaultOllamaProvider()
		if p.OllamaURL != "" {
			out.BaseURL = p.OllamaURL
		}
		if p.OllamaModel != "" {
			out.Model = p.OllamaModel
		}
		if p.OllamaTimeout > 0 {
			out.Timeout = p.OllamaTimeout
		}
		return out, nil
	case "gemini", "google", "hosted":
		out := DefaultGeminiProvider()
		if p.GeminiModel != "" {
			out.Model = p.GeminiModel
		}
		if p.GeminiTimeout > 0 {
			out.Timeout = p.GeminiTimeout
		}
		return out, nil
	case "off":
		return nil, fmt.Errorf("LLM mode is off")
	default:
		return nil, fmt.Errorf("unknown llm mode %q (use ollama|gemini|off)", p.Mode)
	}
}

package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Engine string

const (
	EngineSecrets Engine = "secrets"
	EngineDeps    Engine = "deps"
	EngineSAST    Engine = "sast"
	EngineTaint   Engine = "taint"
	EngineSymEx   Engine = "symex"
	EngineAI      Engine = "ai"
)

type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type TraceStep struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

type Patch struct {
	UnifiedDiff string `json:"unified_diff,omitempty"`
}

type Finding struct {
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	Severity        Severity    `json:"severity"`
	Confidence      float64     `json:"confidence"`
	PrimaryLocation Location    `json:"primary_location"`
	Trace           []TraceStep `json:"trace,omitempty"`

	Explanation string `json:"explanation,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Impact      string `json:"impact,omitempty"`
	Fix         string `json:"fix,omitempty"`
	Patch       *Patch `json:"patch,omitempty"`

	Source    Engine    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

type Report struct {
	TargetPath  string    `json:"target_path"`
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
}

func (r Report) MarshalJSON() ([]byte, error) {
	type Alias Report
	return json.MarshalIndent(Alias(r), "", "  ")
}

func NormalizePath(path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	clean = filepath.ToSlash(clean)
	return clean
}

func StableID(engine Engine, typ string, loc Location, extra string) string {
	base := fmt.Sprintf("%s|%s|%s|%d|%s", engine, strings.ToUpper(typ), NormalizePath(loc.File), loc.StartLine, extra)
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:16])
}

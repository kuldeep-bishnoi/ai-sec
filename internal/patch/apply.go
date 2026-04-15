package patch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sourcegraph/go-diff/diff"
)

type ApplyResult struct {
	AppliedFiles []string
}

// ApplyUnifiedDiff applies a unified diff to files under repoRoot.
// It is intentionally strict: if the diff can’t be applied cleanly, it fails.
func ApplyUnifiedDiff(repoRoot string, unified string) (ApplyResult, error) {
	if strings.TrimSpace(unified) == "" {
		return ApplyResult{}, nil
	}

	files, err := diff.ParseMultiFileDiff([]byte(unified))
	if err != nil {
		return ApplyResult{}, fmt.Errorf("parse diff: %w", err)
	}
	if len(files) == 0 {
		return ApplyResult{}, nil
	}

	var applied []string
	for _, fd := range files {
		path := pickPath(fd)
		if path == "" {
			return ApplyResult{}, fmt.Errorf("diff missing file path")
		}
		if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return ApplyResult{}, fmt.Errorf("refusing to apply patch to path %q", path)
		}
		abs := filepath.Join(repoRoot, filepath.FromSlash(path))

		origBytes, err := os.ReadFile(abs)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("read %s: %w", path, err)
		}
		origLines := splitLines(string(origBytes))

		newLines, err := applyFileHunks(origLines, fd.Hunks)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("apply hunks %s: %w", path, err)
		}
		newContent := strings.Join(newLines, "\n")
		if !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		if err := os.WriteFile(abs, []byte(newContent), 0o644); err != nil {
			return ApplyResult{}, fmt.Errorf("write %s: %w", path, err)
		}
		applied = append(applied, path)
	}

	// Audit trail.
	auditDir := filepath.Join(repoRoot, ".ai-sec", "patches")
	_ = os.MkdirAll(auditDir, 0o755)
	auditPath := filepath.Join(auditDir, time.Now().UTC().Format("20060102T150405Z")+".diff")
	_ = os.WriteFile(auditPath, []byte(unified), 0o644)

	return ApplyResult{AppliedFiles: applied}, nil
}

func pickPath(fd *diff.FileDiff) string {
	// Prefer “new” path.
	p := strings.TrimSpace(strings.TrimPrefix(fd.NewName, "b/"))
	if p == "" || p == "/dev/null" {
		p = strings.TrimSpace(strings.TrimPrefix(fd.OrigName, "a/"))
	}
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
	}
	return p
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "\n")
}

func applyFileHunks(lines []string, hunks []*diff.Hunk) ([]string, error) {
	out := append([]string(nil), lines...)
	// Apply hunks in order; offsets shift, so we track a running delta.
	delta := 0
	for _, h := range hunks {
		start := int(h.OrigStartLine) - 1 + delta
		if start < 0 {
			start = 0
		}
		hlines := splitLines(string(h.Body))

		var newBlock []string
		removeCount := 0
		for _, l := range hlines {
			if l == `\ No newline at end of file` {
				continue
			}
			if len(l) == 0 {
				continue
			}
			switch l[0] {
			case ' ':
				// context line
				newBlock = append(newBlock, l[1:])
				removeCount++
			case '-':
				// removed line
				removeCount++
			case '+':
				newBlock = append(newBlock, l[1:])
			default:
				// ignore unknown
			}
		}

		if start+removeCount > len(out) {
			return nil, fmt.Errorf("hunk out of range")
		}

		// Validate context matches where possible.
		contextIdx := 0
		for _, l := range hlines {
			if l == `\ No newline at end of file` {
				continue
			}
			if len(l) == 0 {
				continue
			}
			if l[0] == ' ' || l[0] == '-' {
				if start+contextIdx >= len(out) {
					return nil, fmt.Errorf("context out of range")
				}
				if l[0] == ' ' {
					if out[start+contextIdx] != l[1:] {
						return nil, fmt.Errorf("context mismatch at line %d", start+contextIdx+1)
					}
				}
				contextIdx++
			}
		}

		// Splice.
		out = append(out[:start], append(newBlock, out[start+removeCount:]...)...)
		delta += len(newBlock) - removeCount
	}
	return out, nil
}

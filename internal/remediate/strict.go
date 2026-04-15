package remediate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sourcegraph/go-diff/diff"
)

type StrictResult struct {
	ChecksRun []string
}

// ValidateStrict runs best-effort language checks. In strict mode, at least one check
// must run and all must succeed.
func ValidateStrict(ctx context.Context, repoRoot string, touchedFiles []string, checkCmd string) (StrictResult, error) {
	any := false
	var checks []string

	run := func(name string, args ...string) error {
		any = true
		checks = append(checks, name+" "+strings.Join(args, " "))
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s failed: %w\n%s", name, err, string(out))
		}
		return nil
	}

	if strings.TrimSpace(checkCmd) != "" {
		any = true
		checks = append(checks, "sh -lc "+checkCmd)
		cmd := exec.CommandContext(ctx, "sh", "-lc", checkCmd)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return StrictResult{ChecksRun: checks}, fmt.Errorf("custom check-cmd failed: %w\n%s", err, string(out))
		}
		return StrictResult{ChecksRun: checks}, nil
	}

	// Go: gofmt touched go files + go test.
	if fileExists(filepath.Join(repoRoot, "go.mod")) {
		var goFiles []string
		for _, f := range touchedFiles {
			if strings.HasSuffix(f, ".go") {
				goFiles = append(goFiles, f)
			}
		}
		if len(goFiles) > 0 {
			args := append([]string{"-w"}, goFiles...)
			if err := run("gofmt", args...); err != nil {
				return StrictResult{ChecksRun: checks}, err
			}
		}
		// go test is our strongest “don’t break functionality” gate.
		if err := run("go", "test", "./..."); err != nil {
			return StrictResult{ChecksRun: checks}, err
		}
	}

	// Python: compileall
	if hasAnyExt(repoRoot, ".py") {
		if err := run("python3", "-m", "compileall", "."); err != nil {
			return StrictResult{ChecksRun: checks}, err
		}
		// Optional: ruff/flake8 if installed.
		if _, err := exec.LookPath("ruff"); err == nil {
			if err := run("ruff", "check", "."); err != nil {
				return StrictResult{ChecksRun: checks}, err
			}
		} else if _, err := exec.LookPath("flake8"); err == nil {
			if err := run("flake8"); err != nil {
				return StrictResult{ChecksRun: checks}, err
			}
		}
	}

	// JS/TS: npm run lint if package.json exists.
	if fileExists(filepath.Join(repoRoot, "package.json")) {
		// Prefer project script if present; else fallback to eslint if available.
		if err := run("npm", "run", "lint"); err != nil {
			if _, lpErr := exec.LookPath("npx"); lpErr == nil {
				if err2 := run("npx", "eslint", "."); err2 != nil {
					return StrictResult{ChecksRun: checks}, err
				}
			} else {
				return StrictResult{ChecksRun: checks}, err
			}
		}
	}

	if !any {
		return StrictResult{ChecksRun: checks}, errors.New("strict validation: no applicable checks found (refusing to apply)")
	}
	return StrictResult{ChecksRun: checks}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hasAnyExt(root string, ext string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if found || err != nil {
			return nil
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == ".ai-sec" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ext) {
			found = true
		}
		return nil
	})
	return found
}

func TouchedFilesFromDiff(unified string) ([]string, error) {
	files, err := diff.ParseMultiFileDiff([]byte(unified))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, fd := range files {
		p := strings.TrimSpace(strings.TrimPrefix(fd.NewName, "b/"))
		if p == "" || p == "/dev/null" {
			p = strings.TrimSpace(strings.TrimPrefix(fd.OrigName, "a/"))
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
		if p != "" && p != "/dev/null" {
			out = append(out, p)
		}
	}
	return out, nil
}

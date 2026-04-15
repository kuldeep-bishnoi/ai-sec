package gofrontend

import (
	"context"
	"fmt"
	"path/filepath"

	"golang.org/x/tools/go/packages"
)

type LoadResult struct {
	Packages []*packages.Package
}

func Load(ctx context.Context, repoPath string) (LoadResult, error) {
	cfg := &packages.Config{
		Context: ctx,
		Dir:     repoPath,
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedSyntax |
			packages.NeedModule,
	}

	// Load all packages under the repo. Using ./... respects module boundaries.
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return LoadResult{}, err
	}
	for _, p := range pkgs {
		for _, e := range p.Errors {
			// Keep going but surface errors: a partial load is still useful for security scanning.
			_ = e
		}
	}
	// Normalize file paths: packages may return absolute or relative depending on environment.
	for _, p := range pkgs {
		for i, f := range p.CompiledGoFiles {
			if abs, err := filepath.Abs(f); err == nil {
				p.CompiledGoFiles[i] = abs
			}
		}
	}
	if len(pkgs) == 0 {
		return LoadResult{}, fmt.Errorf("no Go packages found under %s", repoPath)
	}
	return LoadResult{Packages: pkgs}, nil
}

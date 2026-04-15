package goanalyzer

import (
	"ai-sec/internal/graph"
	gofrontend "ai-sec/internal/lang/go"
	"context"
)

type Result struct {
	SSA   gofrontend.SSAResult
	Graph *graph.Graph
}

func Analyze(ctx context.Context, repoPath string) (Result, error) {
	lr, err := gofrontend.Load(ctx, repoPath)
	if err != nil {
		// No Go packages is not fatal at repository level.
		return Result{}, err
	}
	ssaRes, err := gofrontend.BuildSSA(lr.Packages)
	if err != nil {
		return Result{}, err
	}
	g := gofrontend.BuildGraphFromCallGraph(ssaRes.Fset, ssaRes.CallGraph)
	return Result{SSA: ssaRes, Graph: g}, nil
}

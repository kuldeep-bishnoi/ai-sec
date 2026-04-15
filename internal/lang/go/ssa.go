package gofrontend

import (
	"ai-sec/internal/graph"
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type SSAResult struct {
	Program   *ssa.Program
	Packages  []*ssa.Package
	MainPkgs  []*ssa.Package
	CallGraph *callgraph.Graph
	Fset      *token.FileSet
}

func BuildSSA(pkgs []*packages.Package) (SSAResult, error) {
	if len(pkgs) == 0 {
		return SSAResult{}, nil
	}
	fset := pkgs[0].Fset
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
	prog.Build()

	// ssautil.AllPackages may return nil entries for packages that failed to type-check.
	// Never let that crash analysis; filter nils before MainPackages().
	nonNil := make([]*ssa.Package, 0, len(ssaPkgs))
	for _, p := range ssaPkgs {
		if p != nil {
			nonNil = append(nonNil, p)
		}
	}

	var mainPkgs []*ssa.Package
	if len(nonNil) > 0 {
		mainPkgs = ssautil.MainPackages(nonNil)
	}
	cg := cha.CallGraph(prog)

	return SSAResult{
		Program:   prog,
		Packages:  nonNil,
		MainPkgs:  mainPkgs,
		CallGraph: cg,
		Fset:      fset,
	}, nil
}

func BuildGraphFromCallGraph(fset *token.FileSet, cg *callgraph.Graph) *graph.Graph {
	g := &graph.Graph{
		Functions: map[string]*graph.Function{},
		Calls:     nil,
	}
	if cg == nil {
		return g
	}

	for fn, node := range cg.Nodes {
		if fn == nil || node == nil {
			continue
		}
		id := fn.String()
		if _, ok := g.Functions[id]; !ok {
			pos := token.Position{}
			if fset != nil && fn.Pos() != token.NoPos {
				pos = fset.Position(fn.Pos())
			}
			pkgPath := ""
			if fn.Pkg != nil && fn.Pkg.Pkg != nil {
				pkgPath = fn.Pkg.Pkg.Path()
			}
			g.Functions[id] = &graph.Function{
				ID:        id,
				Name:      fn.Name(),
				Package:   pkgPath,
				File:      pos.Filename,
				StartLine: pos.Line,
				EndLine:   0,
			}
		}

		for _, e := range node.Out {
			if e == nil || e.Callee == nil || e.Callee.Func == nil {
				continue
			}
			line := 0
			file := ""
			if fset != nil && e.Site != nil && e.Site.Pos() != token.NoPos {
				p := fset.Position(e.Site.Pos())
				file, line = p.Filename, p.Line
			}
			g.Calls = append(g.Calls, graph.CallEdge{
				CallerID: id,
				CalleeID: e.Callee.Func.String(),
				File:     file,
				Line:     line,
			})
		}
	}
	return g
}

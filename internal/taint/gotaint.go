package taint

import (
	"ai-sec/internal/findings"
	"ai-sec/internal/symex"
	"context"
	"go/token"
	"strings"
	"time"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type GoResult struct {
	Findings []findings.Finding
}

type taintInfo struct {
	origin ssa.Instruction
	trace  []findings.TraceStep
}

func AnalyzeGo(ctx context.Context, fset *token.FileSet, prog *ssa.Program) (GoResult, error) {
	_ = ctx
	if prog == nil {
		return GoResult{}, nil
	}

	allFns := ssautil.AllFunctions(prog)
	var out []findings.Finding

	for fn := range allFns {
		if fn == nil || fn.Blocks == nil {
			continue
		}
		// Skip synthetic wrappers where we can’t map locations well.
		if fn.Synthetic != "" {
			continue
		}
		fs := analyzeGoFunction(fset, fn)
		out = append(out, fs...)
	}

	return GoResult{Findings: out}, nil
}

func analyzeGoFunction(fset *token.FileSet, fn *ssa.Function) []findings.Finding {
	tainted := map[ssa.Value]taintInfo{}
	var findingsOut []findings.Finding

	mark := func(v ssa.Value, instr ssa.Instruction, reason string, inherited []findings.TraceStep) {
		if v == nil {
			return
		}
		if _, ok := tainted[v]; ok {
			return
		}
		step := traceStepForInstr(fset, instr, reason)
		trace := append([]findings.TraceStep(nil), inherited...)
		trace = append(trace, step)
		tainted[v] = taintInfo{origin: instr, trace: trace}
	}

	isTainted := func(v ssa.Value) (taintInfo, bool) {
		if v == nil {
			return taintInfo{}, false
		}
		ti, ok := tainted[v]
		return ti, ok
	}

	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			switch ins := instr.(type) {
			case *ssa.Call:
				common := ins.Call
				static := common.StaticCallee()
				if static != nil && isSourceCallee(static) {
					mark(ins, ins, "source: user-controlled input", nil)
				}

				// Propagate taint through call results when any arg is tainted.
				var inherited []findings.TraceStep
				for _, a := range common.Args {
					if ti, ok := isTainted(a); ok {
						inherited = ti.trace
						break
					}
				}
				if inherited != nil && ins != nil {
					mark(ins, ins, "propagated through call", inherited)
				}

				// Sinks.
				if static != nil && isSinkCallee(static) {
					if hit, ti := sinkHasTaintedArg(common.Args, isTainted); hit {
						constraints := symex.SummarizeConstraints(fset, fn, b, 8)
						fullTrace := append([]findings.TraceStep(nil), ti.trace...)
						fullTrace = append(fullTrace, constraints...)

						f := findingForSink(fset, ins, static, fullTrace)
						if f.ID != "" {
							findingsOut = append(findingsOut, f)
						}

						if len(constraints) > 0 {
							findingsOut = append(findingsOut, findings.Finding{
								ID:              findings.StableID(findings.EngineSymEx, f.Type+" (Symbolic Path)", f.PrimaryLocation, static.String()),
								Type:            f.Type + " (Symbolic Path)",
								Severity:        f.Severity,
								Confidence:      0.55,
								PrimaryLocation: f.PrimaryLocation,
								Trace:           constraints,
								Explanation:     "A feasible control-flow path to the sink was found; constraints summarize one path from entry to the sink.",
								Fix:             f.Fix,
								Source:          findings.EngineSymEx,
								CreatedAt:       time.Now(),
							})
						}
					}
				}

			case *ssa.BinOp:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via binary op", ti.trace)
				} else if ti, ok := isTainted(ins.Y); ok {
					mark(ins, ins, "propagated via binary op", ti.trace)
				}
			case *ssa.Phi:
				for _, e := range ins.Edges {
					if ti, ok := isTainted(e); ok {
						mark(ins, ins, "propagated via phi", ti.trace)
						break
					}
				}
			case *ssa.UnOp:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via unary op", ti.trace)
				}
			case *ssa.ChangeType:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via type change", ti.trace)
				}
			case *ssa.MakeInterface:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via interface wrap", ti.trace)
				}
			case *ssa.Field:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via field read", ti.trace)
				}
			case *ssa.Index:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via index read", ti.trace)
				}
			case *ssa.Slice:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via slice", ti.trace)
				}
			case *ssa.Convert:
				if ti, ok := isTainted(ins.X); ok {
					mark(ins, ins, "propagated via convert", ti.trace)
				}
			}
		}
	}

	return findingsOut
}

func traceStepForInstr(fset *token.FileSet, instr ssa.Instruction, msg string) findings.TraceStep {
	loc := findings.Location{}
	if fset != nil && instr != nil && instr.Pos() != token.NoPos {
		p := fset.Position(instr.Pos())
		loc = findings.Location{File: findings.NormalizePath(p.Filename), StartLine: p.Line, EndLine: p.Line}
	}
	return findings.TraceStep{Location: loc, Message: msg}
}

func isSourceCallee(fn *ssa.Function) bool {
	name := fn.String()
	// HTTP sources
	if strings.Contains(name, "(*net/http.Request).FormValue") {
		return true
	}
	if strings.Contains(name, "(*net/http.Request).PostFormValue") {
		return true
	}
	if strings.Contains(name, "(net/url.Values).Get") {
		return true
	}
	// Env sources
	if strings.HasPrefix(name, "os.Getenv") {
		return true
	}
	// Header reads are often user-controlled.
	if strings.Contains(name, "(*net/http.Header).Get") {
		return true
	}
	return false
}

func isSinkCallee(fn *ssa.Function) bool {
	name := fn.String()
	// SQL sinks
	if strings.Contains(name, "(*database/sql.DB).Query") ||
		strings.Contains(name, "(*database/sql.DB).Exec") ||
		strings.Contains(name, "(*database/sql.Tx).Query") ||
		strings.Contains(name, "(*database/sql.Tx).Exec") ||
		strings.Contains(name, "(*database/sql.Stmt).Query") ||
		strings.Contains(name, "(*database/sql.Stmt).Exec") {
		return true
	}
	// Command execution sinks
	if strings.HasPrefix(name, "os/exec.Command") || strings.HasPrefix(name, "os/exec.CommandContext") {
		return true
	}
	// SSRF-ish sinks
	if strings.HasPrefix(name, "net/http.Get") || strings.HasPrefix(name, "net/http.Post") {
		return true
	}
	if strings.Contains(name, "(*net/http.Client).Do") {
		return true
	}
	return false
}

func sinkHasTaintedArg(args []ssa.Value, isTainted func(ssa.Value) (taintInfo, bool)) (bool, taintInfo) {
	for _, a := range args {
		if ti, ok := isTainted(a); ok {
			return true, ti
		}
	}
	return false, taintInfo{}
}

func findingForSink(fset *token.FileSet, call *ssa.Call, callee *ssa.Function, trace []findings.TraceStep) findings.Finding {
	pos := token.Position{}
	if fset != nil && call != nil && call.Pos() != token.NoPos {
		pos = fset.Position(call.Pos())
	}
	loc := findings.Location{File: findings.NormalizePath(pos.Filename), StartLine: pos.Line, EndLine: pos.Line}

	calleeName := ""
	if callee != nil {
		calleeName = callee.String()
	}

	typ := "Tainted Dataflow"
	sev := findings.SeverityMedium
	expl := "User-controlled input appears to flow into a sensitive sink."
	fix := "Validate, sanitize, or use safe APIs (e.g., parameterized queries) to prevent injection."

	switch {
	case strings.Contains(calleeName, "database/sql"):
		typ = "SQL Injection"
		sev = findings.SeverityCritical
		expl = "User-controlled input appears to reach a SQL query/exec call without a proven parameterization boundary."
		fix = "Use parameterized queries/prepared statements and avoid string concatenation when building SQL."
	case strings.HasPrefix(calleeName, "os/exec.Command"):
		typ = "Command Injection"
		sev = findings.SeverityCritical
		expl = "User-controlled input appears to reach command execution (`os/exec.Command`) without strict allowlisting."
		fix = "Avoid invoking shells, use strict allowlists, and pass arguments as separate parameters (never concatenate)."
	case strings.HasPrefix(calleeName, "net/http.Get") || strings.Contains(calleeName, "(*net/http.Client).Do"):
		typ = "SSRF"
		sev = findings.SeverityHigh
		expl = "User-controlled input appears to influence an outbound HTTP request target."
		fix = "Enforce allowlists for hosts/IP ranges, block link-local/meta-data IPs, and validate URLs before requests."
	}

	return findings.Finding{
		ID:              findings.StableID(findings.EngineTaint, typ, loc, calleeName),
		Type:            typ,
		Severity:        sev,
		Confidence:      0.65,
		PrimaryLocation: loc,
		Trace:           trace,
		Explanation:     expl,
		Fix:             fix,
		Source:          findings.EngineTaint,
		CreatedAt:       time.Now(),
	}
}

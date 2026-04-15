package symex

import (
	"ai-sec/internal/findings"
	"fmt"
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// SummarizeConstraints produces a lightweight "symbolic-ish" constraint summary for one
// path from function entry to the target block. This is intentionally bounded and
// meant for evidence/triage, not full correctness.
func SummarizeConstraints(fset *token.FileSet, fn *ssa.Function, target *ssa.BasicBlock, maxConstraints int) []findings.TraceStep {
	if fn == nil || target == nil || len(fn.Blocks) == 0 {
		return nil
	}
	entry := fn.Blocks[0]
	if entry == target {
		return nil
	}

	type predInfo struct {
		prev *ssa.BasicBlock
		via  *ssa.If
		// succIndex indicates which successor of via was taken (0/1) when known.
		succIndex int
	}

	// BFS over blocks to find a path to target.
	queue := []*ssa.BasicBlock{entry}
	seen := map[*ssa.BasicBlock]bool{entry: true}
	preds := map[*ssa.BasicBlock]predInfo{}

	for len(queue) > 0 && !seen[target] {
		b := queue[0]
		queue = queue[1:]

		var viaIf *ssa.If
		if len(b.Instrs) > 0 {
			if ins, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If); ok {
				viaIf = ins
			}
		}

		for i, s := range b.Succs {
			if s == nil || seen[s] {
				continue
			}
			seen[s] = true
			preds[s] = predInfo{prev: b, via: viaIf, succIndex: i}
			queue = append(queue, s)
		}
	}

	if !seen[target] {
		return nil
	}

	// Reconstruct path backwards.
	var path []*ssa.BasicBlock
	for cur := target; cur != nil; {
		path = append(path, cur)
		if cur == entry {
			break
		}
		pi, ok := preds[cur]
		if !ok || pi.prev == nil {
			break
		}
		cur = pi.prev
	}

	// Walk path forward and gather constraints from controlling Ifs.
	// (path is currently reversed)
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	var out []findings.TraceStep
	for idx := 0; idx < len(path)-1 && len(out) < maxConstraints; idx++ {
		next := path[idx+1]
		pi, ok := preds[next]
		if !ok || pi.via == nil {
			continue
		}

		cond := "<cond>"
		if pi.via.Cond != nil {
			cond = pi.via.Cond.String()
		}
		var constraint string
		switch pi.succIndex {
		case 0:
			constraint = fmt.Sprintf("path constraint: %s == true", cond)
		case 1:
			constraint = fmt.Sprintf("path constraint: %s == false", cond)
		default:
			constraint = fmt.Sprintf("path constraint: %s", cond)
		}

		loc := findings.Location{}
		if fset != nil && pi.via.Pos() != token.NoPos {
			p := fset.Position(pi.via.Pos())
			loc = findings.Location{File: findings.NormalizePath(p.Filename), StartLine: p.Line, EndLine: p.Line}
		}
		out = append(out, findings.TraceStep{Location: loc, Message: constraint})
	}
	return out
}

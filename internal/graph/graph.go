package graph

// Graph is a minimal language-agnostic code graph.
// It’s intentionally small in v1: the taint engine consumes it, and we can enrich later.
type Graph struct {
	Functions map[string]*Function // keyed by fully-qualified name
	Calls     []CallEdge
}

type Function struct {
	ID        string
	Name      string
	Package   string
	File      string
	StartLine int
	EndLine   int
}

type CallEdge struct {
	CallerID string
	CalleeID string
	File     string
	Line     int
}

package callgraph

type TraversalOptions struct {
	MaxDepth int

	IncludeLibraries bool

	OnlyReachableFromExternal bool
}

type PathFinder struct {
	cg   *CallGraph
	opts TraversalOptions
}

func NewPathFinder(cg *CallGraph, opts TraversalOptions) *PathFinder {
	if opts.MaxDepth == 0 {
		opts.MaxDepth = 20
	}
	return &PathFinder{cg: cg, opts: opts}
}

// DFS + cycle detection ile.
func (pf *PathFinder) AllPaths(from, to FunctionID) [][]FunctionID {
	var paths [][]FunctionID
	visited := make(map[FunctionID]bool)
	current := []FunctionID{from}

	pf.dfs(from, to, current, visited, &paths, 0)
	return paths
}

func (pf *PathFinder) dfs(
	current, target FunctionID,
	path []FunctionID,
	visited map[FunctionID]bool,
	paths *[][]FunctionID,
	depth int,
) {
	if depth > pf.opts.MaxDepth {
		return
	}

	if current == target && depth > 0 {
		p := make([]FunctionID, len(path))
		copy(p, path)
		*paths = append(*paths, p)
		return
	}

	if visited[current] {
		return
	}

	visited[current] = true
	defer func() { visited[current] = false }()

	node, ok := pf.cg.Nodes[current]
	if !ok {
		return
	}

	for _, cs := range node.Callees {
		if !cs.IsResolved {
			continue
		}
		if !pf.opts.IncludeLibraries && cs.Kind == CallLibrary {
			continue
		}
		pf.dfs(
			cs.Callee, target,
			append(path, cs.Callee),
			visited, paths, depth+1,
		)
	}
}

type ReachabilityMatrix struct {
	matrix map[FunctionID]map[FunctionID]bool
}

func BuildReachabilityMatrix(cg *CallGraph) *ReachabilityMatrix {
	rm := &ReachabilityMatrix{
		matrix: make(map[FunctionID]map[FunctionID]bool),
	}

	for id := range cg.Nodes {
		rm.matrix[id] = make(map[FunctionID]bool)
		reachable := cg.TransitiveCallees(id)
		for _, r := range reachable {
			rm.matrix[id][r.ID] = true
		}
	}

	return rm
}

func (rm *ReachabilityMatrix) CanReach(from, to FunctionID) bool {
	if m, ok := rm.matrix[from]; ok {
		return m[to]
	}
	return false
}

type CycleAnalyzer struct {
	cg     *CallGraph
	cycles [][]FunctionID
}

func NewCycleAnalyzer(cg *CallGraph) *CycleAnalyzer {
	return &CycleAnalyzer{cg: cg, cycles: cg.Cycles}
}

func (ca *CycleAnalyzer) SecurityRelevantCycles() []CycleFinding {
	var findings []CycleFinding

	for _, cycle := range ca.cycles {
		hasExternalCall := false
		hasStateWrite := false

		for _, fnID := range cycle {
			node, ok := ca.cg.Nodes[fnID]
			if !ok {
				continue
			}
			if node.HasExternalCall {
				hasExternalCall = true
			}
			if node.HasStateWrite {
				hasStateWrite = true
			}
		}

		if hasExternalCall {
			findings = append(findings, CycleFinding{
				Cycle:           cycle,
				HasExternalCall: hasExternalCall,
				HasStateWrite:   hasStateWrite,
				Risk:            assessCycleRisk(hasExternalCall, hasStateWrite),
			})
		}
	}

	return findings
}

type CycleFinding struct {
	Cycle           []FunctionID
	HasExternalCall bool
	HasStateWrite   bool
	Risk            string
}

func assessCycleRisk(hasExtCall, hasStateWrite bool) string {
	switch {
	case hasExtCall && hasStateWrite:
		return "CRITICAL: Reentrancy cycle — external call + state write in loop"
	case hasExtCall:
		return "HIGH: External call in recursive cycle"
	default:
		return "MEDIUM: Recursive cycle without external call"
	}
}

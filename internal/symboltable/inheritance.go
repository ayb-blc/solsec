package symboltable

import "github.com/ayb-blc/solsec/internal/parser"

type InheritanceGraph struct {
	direct map[string][]string

	ancestors map[string]map[string]bool

	resolved bool
}

func NewInheritanceGraph() *InheritanceGraph {
	return &InheritanceGraph{
		direct:    make(map[string][]string),
		ancestors: make(map[string]map[string]bool),
	}
}

func (g *InheritanceGraph) AddContract(name string, parents []string) {
	g.direct[name] = parents
	g.resolved = false
}

func (g *InheritanceGraph) Resolve() {
	if g.resolved {
		return
	}
	visited := make(map[string]bool)
	for name := range g.direct {
		g.resolveOne(name, visited)
	}
	g.resolved = true
}

func (g *InheritanceGraph) resolveOne(name string, visited map[string]bool) map[string]bool {
	if anc, ok := g.ancestors[name]; ok {
		return anc
	}
	if visited[name] {
		return make(map[string]bool)
	}
	visited[name] = true

	anc := make(map[string]bool)
	for _, parent := range g.direct[name] {
		anc[parent] = true
		for k := range g.resolveOne(parent, visited) {
			anc[k] = true
		}
	}
	g.ancestors[name] = anc
	return anc
}

func (g *InheritanceGraph) InheritsFrom(contractName, parentName string) bool {
	if !g.resolved {
		g.Resolve()
	}
	return g.ancestors[contractName][parentName]
}

func (g *InheritanceGraph) DirectParents(contractName string) []string {
	return g.direct[contractName]
}

func (g *InheritanceGraph) AllAncestors(contractName string) map[string]bool {
	if !g.resolved {
		g.Resolve()
	}
	out := make(map[string]bool, len(g.ancestors[contractName]))
	for k, v := range g.ancestors[contractName] {
		out[k] = v
	}
	return out
}

func BuildInheritanceGraph(unit *parser.SourceUnit) *InheritanceGraph {
	g := NewInheritanceGraph()
	if unit == nil {
		return g
	}
	for _, node := range unit.Nodes {
		if node.NodeType != "ContractDefinition" || node.ContractDef == nil {
			continue
		}
		cd := node.ContractDef
		parents := make([]string, 0, len(cd.BaseContracts))
		for _, base := range cd.BaseContracts {
			if name := base.BaseName.Name; name != "" {
				parents = append(parents, name)
			}
		}
		g.AddContract(cd.Name, parents)
	}
	g.Resolve()
	return g
}

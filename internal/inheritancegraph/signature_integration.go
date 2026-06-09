package inheritancegraph

// EnrichFunctions computes canonical ABI signatures, selectors, and normalized
// parameter metadata for every function in the graph.
func (g *Graph) EnrichFunctions() {
	resolver := NewSignatureResolver()
	for _, contract := range g.AllContracts() {
		for _, fn := range contract.Functions {
			parsed := resolver.Parse(fn.Signature)
			if parsed == nil {
				parsed = resolver.Parse(fn.Name + "(" + fn.Params + ")")
			}
			if parsed == nil {
				continue
			}
			fn.Canonical = parsed.Canonical
			fn.Selector = parsed.Selector
			fn.NormalizedParams = append([]ParamType(nil), parsed.Params...)
			fn.NormalizedReturns = append([]ParamType(nil), parsed.Returns...)
		}
	}
}

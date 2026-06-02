package analyzer

import (
	"os"

	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
	"github.com/ayb-blc/solsec/internal/taint"
)

type AdvancedPipeline struct {
	solcRunner *parser.SolcRunner
	config     AdvancedConfig
}

type AdvancedConfig struct {
	EnableInterproceduralTaint bool
	EnableStorageTaint         bool
	EnableSummaryBuild         bool
	EnableCycleAnalysis        bool
	MaxCallDepth               int
}

func DefaultAdvancedConfig() AdvancedConfig {
	return AdvancedConfig{
		EnableInterproceduralTaint: true,
		EnableStorageTaint:         true,
		EnableSummaryBuild:         true,
		EnableCycleAnalysis:        true,
		MaxCallDepth:               15,
	}
}

func NewAdvancedPipeline(solcRunner *parser.SolcRunner, config AdvancedConfig) *AdvancedPipeline {
	if solcRunner == nil {
		solcRunner = parser.NewSolcRunner("")
	}
	if isZeroAdvancedConfig(config) {
		config = DefaultAdvancedConfig()
	}
	if config.MaxCallDepth == 0 {
		config.MaxCallDepth = DefaultAdvancedConfig().MaxCallDepth
	}
	return &AdvancedPipeline{
		solcRunner: solcRunner,
		config:     config,
	}
}

func isZeroAdvancedConfig(config AdvancedConfig) bool {
	return !config.EnableInterproceduralTaint &&
		!config.EnableStorageTaint &&
		!config.EnableSummaryBuild &&
		!config.EnableCycleAnalysis &&
		config.MaxCallDepth == 0
}

// AnalyzeFile runs the AST-backed analysis pipeline for one source file.
func (p *AdvancedPipeline) AnalyzeFile(filePath string) (*AdvancedResult, error) {
	if p.solcRunner == nil {
		p.solcRunner = parser.NewSolcRunner("")
	}

	unit, err := p.solcRunner.ParseFile(filePath)
	if err != nil {
		return nil, err
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	content := string(contentBytes)

	srcMap := parser.NewSourceMap(content)

	table, err := symboltable.Build(unit, srcMap)
	if err != nil {
		return nil, err
	}

	cg, err := callgraph.Build(unit, table)
	if err != nil {
		return nil, err
	}

	result := &AdvancedResult{
		Filepath:  filePath,
		CallGraph: cg,
		Table:     table,
	}

	if p.config.EnableSummaryBuild {
		builder := taint.NewSummaryBuilder(cg, table)
		result.Summaries = builder.BuildAll()
	}

	var storageTaint *taint.StorageTaintTracker
	if p.config.EnableStorageTaint {
		storageTaint = taint.NewStorageTaintTracker(table, cg)
		storageTaint.SeedFromSymbolTable()
		result.StorageTaintReads = storageTaint.PropagateToReads()
	}

	if p.config.EnableInterproceduralTaint {
		engine := taint.NewInterproceduralEngine(cg, table, unit)
		result.TaintFlows = engine.Analyze()
	}

	if p.config.EnableCycleAnalysis {
		cycleAnalyzer := callgraph.NewCycleAnalyzer(cg)
		result.SecurityCycles = cycleAnalyzer.SecurityRelevantCycles()
	}

	if len(cg.Nodes) < 200 {
		result.Reachability = callgraph.BuildReachabilityMatrix(cg)
	}

	return result, nil
}

type AdvancedResult struct {
	Filepath          string
	CallGraph         *callgraph.CallGraph
	Table             *symboltable.SymbolTable
	Summaries         map[callgraph.FunctionID]*taint.FunctionSummary
	TaintFlows        []taint.TaintFlow
	StorageTaintReads []taint.StorageTaintRead
	SecurityCycles    []callgraph.CycleFinding
	Reachability      *callgraph.ReachabilityMatrix
}

package intercontract

import (
	"fmt"
	"os"
	"sort"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
)

type PipelineOptions struct {
	EnableTaint bool
	MinSeverity analyzer.Severity
}

func DefaultPipelineOptions() PipelineOptions {
	return PipelineOptions{
		EnableTaint: true,
		MinSeverity: analyzer.Low,
	}
}

type InterContractPipeline struct {
	registry *parser.ParserRegistry
	opts     PipelineOptions
}

func NewInterContractPipeline(registry *parser.ParserRegistry, opts PipelineOptions) *InterContractPipeline {
	if registry == nil {
		registry = parser.DefaultRegistry()
	}
	if opts == (PipelineOptions{}) {
		opts = DefaultPipelineOptions()
	}
	return &InterContractPipeline{registry: registry, opts: opts}
}

type PipelineResult struct {
	Project    *Project
	Graph      *CrossContractCallGraph
	TaintFlows []CrossContractTaintFlow
	Findings   []analyzer.Finding
	Stats      PipelineStats
}

type PipelineStats struct {
	FilesAnalyzed       int
	ContractsFound      int
	FunctionsAnalyzed   int
	CrossContractEdges  int
	UnresolvedCalls     int
	TaintFlows          int
	Findings            int
	FilesWithParseError int
}

func (p *InterContractPipeline) Analyze(root string) (*PipelineResult, error) {
	loader := NewProjectLoader(p.registry)
	project, err := loader.LoadProject(root)
	if err != nil {
		return nil, err
	}

	graph := NewCrossContractGraphBuilder(project).Build()

	var flows []CrossContractTaintFlow
	if p.opts.EnableTaint {
		flows = NewCrossContractTaintEngine(graph, project).Analyze()
	}

	detector := NewCrossContractDetector(graph, project)
	findings := detector.AnalyzeWithTaint(flows)
	findings = filterFindingsBySeverity(findings, p.opts.MinSeverity)

	result := &PipelineResult{
		Project:    project,
		Graph:      graph,
		TaintFlows: flows,
		Findings:   findings,
	}
	result.Stats = computeStats(project, graph, flows, findings)
	return result, nil
}

func (r *PipelineResult) ToAnalysisResults() []analyzer.AnalysisResult {
	if r == nil {
		return nil
	}

	byFile := make(map[string][]analyzer.Finding)
	for _, finding := range r.Findings {
		file := finding.Filepath
		if file == "" {
			file = "<inter-contract>"
		}
		byFile[file] = append(byFile[file], finding)
	}
	for path := range r.Project.Files {
		if _, ok := byFile[path]; !ok {
			byFile[path] = nil
		}
	}

	paths := make([]string, 0, len(byFile))
	for path := range byFile {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	results := make([]analyzer.AnalysisResult, 0, len(paths))
	for _, path := range paths {
		result := analyzer.AnalysisResult{
			Filepath: path,
			Findings: byFile[path],
		}
		if file := r.Project.Files[path]; file != nil && file.Error != nil {
			result.Error = file.Error
		}
		results = append(results, result)
	}
	return results
}

func (r *PipelineResult) PrintStats() {
	if r == nil {
		return
	}
	fmt.Fprintf(os.Stderr,
		"[inter-contract] files=%d contracts=%d functions=%d edges=%d unresolved=%d taint_flows=%d findings=%d\n",
		r.Stats.FilesAnalyzed,
		r.Stats.ContractsFound,
		r.Stats.FunctionsAnalyzed,
		r.Stats.CrossContractEdges,
		r.Stats.UnresolvedCalls,
		r.Stats.TaintFlows,
		r.Stats.Findings,
	)
}

func computeStats(
	project *Project,
	graph *CrossContractCallGraph,
	flows []CrossContractTaintFlow,
	findings []analyzer.Finding,
) PipelineStats {
	stats := PipelineStats{
		FilesAnalyzed: len(project.Files),
		TaintFlows:    len(flows),
		Findings:      len(findings),
	}
	for _, file := range project.Files {
		if file.Error != nil {
			stats.FilesWithParseError++
			continue
		}
		if file.AST != nil {
			stats.ContractsFound += len(file.AST.Contracts)
			for _, contract := range file.AST.Contracts {
				stats.FunctionsAnalyzed += len(contract.Functions)
			}
		}
	}
	if graph != nil {
		stats.UnresolvedCalls = len(graph.UnresolvedCalls)
		for _, node := range graph.Nodes {
			stats.CrossContractEdges += len(node.Callees)
		}
	}
	return stats
}

func filterFindingsBySeverity(findings []analyzer.Finding, min analyzer.Severity) []analyzer.Finding {
	out := findings[:0]
	for _, finding := range findings {
		if finding.Severity >= min {
			out = append(out, finding)
		}
	}
	return out
}

package onchain

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type OnChainPipeline struct {
	analyzer *OnChainAnalyzer
	opts     OnChainPipelineOpts
}

type OnChainPipelineOpts struct {
	// APIKey Etherscan API key
	APIKey string

	Network Network

	LocalSourcePath string

	MinSeverity analyzer.Severity

	CheckExploitHistory bool

	// AnalyzeBytecode bytecode pattern analizi
	AnalyzeBytecode bool

	RunStaticAnalysis bool
}

func DefaultOnChainPipelineOpts(apiKey string, network Network) OnChainPipelineOpts {
	return OnChainPipelineOpts{
		APIKey:              apiKey,
		Network:             network,
		MinSeverity:         analyzer.Low,
		CheckExploitHistory: true,
		AnalyzeBytecode:     true,
		RunStaticAnalysis:   true,
	}
}

func NewOnChainPipeline(opts OnChainPipelineOpts) *OnChainPipeline {
	return &OnChainPipeline{
		analyzer: NewOnChainAnalyzer(opts.APIKey, opts.Network),
		opts:     opts,
	}
}

type OnChainPipelineResult struct {
	Results []*OnChainAnalysisResult

	AllFindings []analyzer.Finding

	// Stats istatistikler
	Stats OnChainStats
}

type OnChainStats struct {
	AddressesAnalyzed   int
	VerifiedContracts   int
	UnverifiedContracts int
	CriticalFindings    int
	BytecodeMismatches  int
	KnownExploited      int
}

func (p *OnChainPipeline) AnalyzeAddresses(
	addresses []ContractAddress,
) (*OnChainPipelineResult, error) {

	pipelineResult := &OnChainPipelineResult{}

	for _, addr := range addresses {
		result, err := p.analyzer.AnalyzeContract(addr, p.opts.LocalSourcePath)
		if err != nil {
			fmt.Printf("[warn] failed to analyze %s: %v\n", addr, err)
			continue
		}

		pipelineResult.Results = append(pipelineResult.Results, result)

		// Stats
		pipelineResult.Stats.AddressesAnalyzed++
		if result.Contract.IsVerified {
			pipelineResult.Stats.VerifiedContracts++
		} else {
			pipelineResult.Stats.UnverifiedContracts++
		}

		// Severity filtresi uygula
		for _, f := range result.StaticFindings {
			if f.Severity >= p.opts.MinSeverity {
				pipelineResult.AllFindings = append(pipelineResult.AllFindings, f)
				if f.Severity == analyzer.Critical {
					pipelineResult.Stats.CriticalFindings++
				}
				if f.DetectorName == "bytecode-mismatch" {
					pipelineResult.Stats.BytecodeMismatches++
				}
			}
		}

		if p.opts.CheckExploitHistory && result.ExploitHistory != nil &&
			len(result.ExploitHistory.KnownExploits) > 0 {
			pipelineResult.Stats.KnownExploited++
			pipelineResult.AllFindings = append(pipelineResult.AllFindings,
				p.exploitHistoryToFinding(addr, result.ExploitHistory))
		}
	}

	return pipelineResult, nil
}

func (p *OnChainPipeline) exploitHistoryToFinding(
	addr ContractAddress,
	history *ExploitHistory,
) analyzer.Finding {
	var descriptions []string
	totalLoss := 0.0
	for _, e := range history.KnownExploits {
		descriptions = append(descriptions, fmt.Sprintf(
			"- %s: %s ($%.0f loss, type: %s)",
			e.Date.Format("2006-01-02"), e.Description, e.LossAmount, e.VulnerabilityType,
		))
		totalLoss += e.LossAmount
	}

	return analyzer.Finding{
		DetectorName: "known-exploited-contract",
		Title: fmt.Sprintf(
			"Contract %s has %d known exploit(s) — total loss: $%.0f",
			addr, len(history.KnownExploits), totalLoss,
		),
		Description: fmt.Sprintf(
			"This contract address has been involved in known exploits:\n%s",
			strings.Join(descriptions, "\n"),
		),
		Recommendation: "Do not interact with this contract. " +
			"If you are the developer, review the vulnerability and deploy a fixed version.",
		Filepath:   fmt.Sprintf("onchain://%s/%s", p.opts.Network, addr),
		Severity:   analyzer.Critical,
		Confidence: analyzer.ConfidenceHigh,
		Tags:       []string{"onchain", "known-exploit", "historical"},
	}
}

func (r *OnChainPipelineResult) ToAnalysisResults() []analyzer.AnalysisResult {
	var results []analyzer.AnalysisResult
	for _, res := range r.Results {
		results = append(results, res.ToAnalysisResult())
	}
	return results
}

func (r *OnChainPipelineResult) PrintStats() {
	s := r.Stats
	fmt.Printf("\n[on-chain analysis]\n")
	fmt.Printf("  addresses:     %d\n", s.AddressesAnalyzed)
	fmt.Printf("  verified:      %d\n", s.VerifiedContracts)
	fmt.Printf("  unverified:    %d\n", s.UnverifiedContracts)
	fmt.Printf("  critical:      %d\n", s.CriticalFindings)
	fmt.Printf("  mismatches:    %d\n", s.BytecodeMismatches)
	fmt.Printf("  known exploited: %d\n", s.KnownExploited)
	fmt.Printf("  total findings: %d\n", len(r.AllFindings))
}

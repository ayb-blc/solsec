package onchain

import (
	"fmt"
	"os"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type OnChainScanner struct {
	fetcher  *SourceFetcher
	detector *ProxyDetector
	ba       *BytecodeAnalyzer
}

func NewOnChainScanner(apiKey string, network Network) *OnChainScanner {
	client := NewEtherscanClient(apiKey, network)
	return &OnChainScanner{
		fetcher:  NewSourceFetcher(client),
		detector: NewProxyDetector(client),
		ba:       NewBytecodeAnalyzer(),
	}
}

type ScanResult struct {
	// Address taranan adres
	Address ContractAddress

	Network Network

	ContractName string

	// IsProxy proxy mi?
	IsProxy bool

	// ProxyInfo proxy bilgisi (IsProxy=true ise)
	ProxyInfo *ProxyInfo

	ProxyRisks []ProxyRisk

	AnalysisResults []analyzer.AnalysisResult

	BytecodeFindings []analyzer.Finding

	FetchError error
}

func (s *OnChainScanner) Scan(
	address ContractAddress,
	analyzerInstance *analyzer.Analyzer,
) (*ScanResult, error) {

	result := &ScanResult{
		Address: address,
		Network: s.fetcher.client.network,
	}

	fetched, err := s.fetcher.Fetch(address)
	if err != nil {
		result.FetchError = err
		// Bytecode analizi yine de yapabiliriz
		bytecode, _ := s.fetcher.client.GetBytecode(address)
		if bytecode != "" {
			result.BytecodeFindings = s.buildBytecodeFindings(address, bytecode)
		}
		return result, nil
	}
	defer fetched.Close()

	result.ContractName = fetched.ContractName
	result.IsProxy = fetched.IsProxy
	if fetched.IsProxy {
		result.ProxyInfo = &ProxyInfo{
			Kind:                  fetched.ProxyKind,
			ImplementationAddress: fetched.Implementation,
			IsUpgradeable:         true,
		}
		result.ProxyRisks = s.detector.AnalyzeProxy(result.ProxyInfo, address)
	}

	analysisResults, err := analyzerInstance.ScanDirectory(fetched.TempDir)
	if err != nil {
		return result, fmt.Errorf("scan failed: %w", err)
	}

	result.AnalysisResults = rewriteFilepaths(
		analysisResults, fetched.TempDir, address, s.fetcher.client.network,
	)

	// 4. Bytecode pattern analizi
	bytecode, _ := s.fetcher.client.GetBytecode(address)
	result.BytecodeFindings = s.buildBytecodeFindings(address, bytecode)

	// 5. Proxy risk finding'lerini ekle
	if len(result.ProxyRisks) > 0 {
		var proxyFindings []analyzer.Finding
		for _, risk := range result.ProxyRisks {
			proxyFindings = append(proxyFindings, proxyRiskToFinding(risk, address, s.fetcher.client.network))
		}
		result.AnalysisResults = append(result.AnalysisResults, analyzer.AnalysisResult{
			Filepath: fmt.Sprintf("onchain://%s/%s/proxy", s.fetcher.client.network, address),
			Findings: proxyFindings,
		})
	}

	return result, nil
}

func (s *OnChainScanner) ScanMultiple(
	addresses []ContractAddress,
	analyzerInstance *analyzer.Analyzer,
) ([]*ScanResult, error) {

	var results []*ScanResult
	for _, addr := range addresses {
		result, err := s.Scan(addr, analyzerInstance)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] scan %s: %v\n", addr, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (r *ScanResult) ToAnalysisResults() []analyzer.AnalysisResult {
	var all []analyzer.AnalysisResult
	all = append(all, r.AnalysisResults...)

	if len(r.BytecodeFindings) > 0 {
		all = append(all, analyzer.AnalysisResult{
			Filepath: fmt.Sprintf("onchain://%s/%s/bytecode", r.Network, r.Address),
			Findings: r.BytecodeFindings,
		})
	}

	return all
}

func (s *OnChainScanner) buildBytecodeFindings(
	address ContractAddress,
	bytecode string,
) []analyzer.Finding {
	patterns := s.ba.AnalyzePatterns(bytecode)

	var findings []analyzer.Finding
	filepath := fmt.Sprintf("onchain://%s/%s", s.fetcher.client.network, address)

	for _, p := range patterns {
		if p.Severity == analyzer.Info {
			continue
		}
		findings = append(findings, analyzer.Finding{
			DetectorName: "onchain-bytecode",
			Title:        fmt.Sprintf("Dangerous opcode in bytecode: %s", p.Opcode),
			Description:  p.Description,
			Filepath:     filepath,
			Severity:     p.Severity,
			Confidence:   analyzer.ConfidenceHigh,
			Tags:         []string{"onchain", "bytecode", p.Name},
		})
	}
	return findings
}

func rewriteFilepaths(
	results []analyzer.AnalysisResult,
	tempDir string,
	address ContractAddress,
	network Network,
) []analyzer.AnalysisResult {
	for i := range results {
		original := results[i].Filepath
		relative := strings.TrimPrefix(original, tempDir)
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			relative = "contract.sol"
		}
		results[i].Filepath = fmt.Sprintf("etherscan://%s/%s/%s",
			network, address, relative)

		for j := range results[i].Findings {
			results[i].Findings[j].Filepath = results[i].Filepath
		}
	}
	return results
}

func proxyRiskToFinding(
	risk ProxyRisk,
	address ContractAddress,
	network Network,
) analyzer.Finding {
	sev := analyzer.Medium
	switch risk.Severity {
	case "critical":
		sev = analyzer.Critical
	case "high":
		sev = analyzer.High
	case "low":
		sev = analyzer.Low
	case "info":
		sev = analyzer.Info
	}

	return analyzer.Finding{
		DetectorName: "proxy-risk",
		Title:        risk.Title,
		Description:  risk.Description,
		Filepath:     fmt.Sprintf("onchain://%s/%s", network, address),
		Severity:     sev,
		Confidence:   analyzer.ConfidenceMedium,
		Tags:         []string{"proxy", "onchain"},
	}
}

package onchain

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// OnChainAnalyzer on-chain contract analizi yapar.
// Etherscan API + Bytecode analizi + Statik analiz entegrasyonu.
type OnChainAnalyzer struct {
	client           *EtherscanClient
	bytecodeAnalyzer *BytecodeAnalyzer
	knownExploitDB   *KnownExploitDB
}

func NewOnChainAnalyzer(apiKey string, network Network) *OnChainAnalyzer {
	return &OnChainAnalyzer{
		client:           NewEtherscanClient(apiKey, network),
		bytecodeAnalyzer: NewBytecodeAnalyzer(),
		knownExploitDB:   NewKnownExploitDB(),
	}
}

func (a *OnChainAnalyzer) FetchContract(address ContractAddress) (*DeployedContract, error) {
	contract := &DeployedContract{
		Address: address,
		Network: a.client.network,
	}

	// Bytecode
	bytecode, err := a.client.GetBytecode(address)
	if err != nil {
		return nil, fmt.Errorf("fetch bytecode: %w", err)
	}
	contract.Bytecode = bytecode

	if bytecode == "" || bytecode == "0x" {
		return nil, fmt.Errorf("address %s is not a contract (EOA or self-destructed)", address)
	}

	source, err := a.client.GetSourceCode(address)
	if err == nil && source != nil {
		contract.IsVerified = true
		contract.VerifiedSource = source
	}

	// Balance
	balance, err := a.client.GetBalance(address)
	if err == nil {
		contract.Balance = balance
	}

	// Deployment bilgisi
	deployment, err := a.client.GetCreationTx(address)
	if err == nil && deployment != nil {
		contract.DeploymentInfo = deployment
	}

	return contract, nil
}

func (a *OnChainAnalyzer) AnalyzeContract(
	address ContractAddress,
	localSourcePath string,
) (*OnChainAnalysisResult, error) {

	result := &OnChainAnalysisResult{
		Address: address,
		Network: a.client.network,
	}

	// On-chain bilgiyi al
	contract, err := a.FetchContract(address)
	if err != nil {
		return nil, err
	}
	result.Contract = contract

	// Bytecode pattern analizi
	result.SuspiciousPatterns = a.bytecodeAnalyzer.AnalyzePatterns(contract.Bytecode)

	result.FunctionSelectors = a.bytecodeAnalyzer.ExtractFunctionSelectors(contract.Bytecode)

	if contract.IsVerified && contract.VerifiedSource != nil {
		findings := a.runStaticAnalysis(contract)
		result.StaticFindings = findings

		if localSourcePath != "" {
			comparison := a.compareWithLocal(contract, localSourcePath)
			result.BytecodeComparison = comparison

			if comparison != nil && !comparison.Match {
				result.StaticFindings = append(result.StaticFindings,
					a.buildMismatchFinding(contract, comparison))
			}
		}
	} else {
		result.StaticFindings = append(result.StaticFindings,
			a.buildUnverifiedFinding(contract))
	}

	result.StaticFindings = append(result.StaticFindings,
		a.patternsToFindings(contract, result.SuspiciousPatterns)...)

	result.ExploitHistory = a.knownExploitDB.Lookup(address)

	return result, nil
}

func (a *OnChainAnalyzer) VerifyBytecode(
	address ContractAddress,
	localBytecode string,
) (*BytecodeComparisonResult, error) {

	onChainBytecode, err := a.client.GetBytecode(address)
	if err != nil {
		return nil, fmt.Errorf("fetch on-chain bytecode: %w", err)
	}

	result := a.bytecodeAnalyzer.Compare(onChainBytecode, localBytecode)
	result.Address = address
	result.Network = a.client.network

	return result, nil
}

func (a *OnChainAnalyzer) runStaticAnalysis(
	contract *DeployedContract,
) []analyzer.Finding {
	if contract.VerifiedSource == nil {
		return nil
	}

	var allFindings []analyzer.Finding
	sources := contract.VerifiedSource.SourceFiles
	if len(sources) == 0 {
		sources = map[string]string{
			contract.VerifiedSource.ContractName + ".sol": contract.VerifiedSource.SourceCode,
		}
	}

	for filename, content := range sources {
		lines := strings.Split(content, "\n")
		filepath := fmt.Sprintf("etherscan://%s/%s/%s",
			a.client.network, contract.Address, filename)

		// Regex-based detector'lar (solc gerektirmeyen)
		detectors := inMemoryDetectors()
		for _, det := range detectors {
			findings, err := det.Analyze(lines, content, filepath)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings
}

func (a *OnChainAnalyzer) compareWithLocal(
	contract *DeployedContract,
	_ string,
) *BytecodeComparisonResult {
	return &BytecodeComparisonResult{
		Address:   contract.Address,
		Network:   a.client.network,
		MatchType: MatchUnverified,
	}
}

func (a *OnChainAnalyzer) patternsToFindings(
	contract *DeployedContract,
	patterns []SuspiciousPattern,
) []analyzer.Finding {
	var findings []analyzer.Finding

	filepath := fmt.Sprintf("onchain://%s/%s", a.client.network, contract.Address)

	for _, p := range patterns {
		if p.Severity == analyzer.Info {
			continue // Bilgilendirme pattern'leri raporlama
		}

		findings = append(findings, analyzer.Finding{
			DetectorName: "onchain-bytecode-pattern",
			Title: fmt.Sprintf(
				"Dangerous opcode in deployed bytecode: %s", p.Opcode,
			),
			Description: fmt.Sprintf(
				"%s\n\nFound at byte offset 0x%x in contract %s on %s.\n"+
					"Byte sequence: %s",
				p.Description, p.Offset, contract.Address, a.client.network, p.ByteSequence,
			),
			Recommendation: opcodeRecommendation(p.Opcode),
			Filepath:       filepath,
			Severity:       p.Severity,
			Confidence:     analyzer.ConfidenceHigh,
			Tags:           []string{"onchain", "bytecode", p.Name},
		})
	}

	return findings
}

func (a *OnChainAnalyzer) buildUnverifiedFinding(
	contract *DeployedContract,
) analyzer.Finding {
	return analyzer.Finding{
		DetectorName: "unverified-contract",
		Title: fmt.Sprintf(
			"Contract %s is not verified on %s",
			contract.Address, a.client.network,
		),
		Description: "The contract source code has not been verified on Etherscan. " +
			"Users cannot audit the code, which significantly increases trust risk. " +
			"The deployed bytecode may differ from any claimed source code.",
		Recommendation: "Verify the contract source code on Etherscan:\n" +
			"  1. Use 'npx hardhat verify' or 'forge verify-contract'\n" +
			"  2. Or manually submit source via Etherscan's verification portal",
		Filepath:   fmt.Sprintf("onchain://%s/%s", a.client.network, contract.Address),
		Severity:   analyzer.High,
		Confidence: analyzer.ConfidenceHigh,
		Tags:       []string{"onchain", "unverified", "transparency"},
	}
}

func (a *OnChainAnalyzer) buildMismatchFinding(
	contract *DeployedContract,
	comparison *BytecodeComparisonResult,
) analyzer.Finding {
	return analyzer.Finding{
		DetectorName: "bytecode-mismatch",
		Title: fmt.Sprintf(
			"CRITICAL: Bytecode mismatch for contract %s", contract.Address,
		),
		Description: fmt.Sprintf(
			"The deployed bytecode does NOT match the verified source code.\n\n"+
				"On-chain hash:  %s\n"+
				"Local hash:     %s\n"+
				"Differences:    %d\n\n"+
				"This indicates the deployed contract may have been tampered with, "+
				"or a different version was deployed than the verified source.",
			comparison.OnChainBytecodeHash,
			comparison.LocalBytecodeHash,
			len(comparison.Differences),
		),
		Recommendation: "IMMEDIATELY investigate the deployment process:\n" +
			"  1. Check deployment scripts for manipulation\n" +
			"  2. Verify the deployer address\n" +
			"  3. Compare deployment transaction bytecode with compiled output\n" +
			"  4. Consider pausing the contract if it has pause functionality",
		Filepath:   fmt.Sprintf("onchain://%s/%s", a.client.network, contract.Address),
		Severity:   analyzer.Critical,
		Confidence: analyzer.ConfidenceHigh,
		Tags:       []string{"onchain", "bytecode-mismatch", "supply-chain"},
	}
}

func opcodeRecommendation(opcode string) string {
	switch opcode {
	case "SELFDESTRUCT":
		return "Remove SELFDESTRUCT if not necessary. If required, protect with strict access control. " +
			"Note: EIP-6049 deprecates SELFDESTRUCT."
	case "DELEGATECALL":
		return "Ensure delegatecall target is immutable or protected. " +
			"Never allow user-controlled addresses as delegatecall targets. " +
			"Use OpenZeppelin's proxy patterns."
	case "ORIGIN":
		return "Replace tx.origin checks with msg.sender for authentication. " +
			"tx.origin is vulnerable to phishing attacks via intermediate contracts."
	case "CALLCODE":
		return "Replace CALLCODE with DELEGATECALL. CALLCODE is deprecated and behaves differently."
	default:
		return "Review the usage of this opcode carefully."
	}
}

// OnChainAnalysisResult tam on-chain analiz sonucu.
type OnChainAnalysisResult struct {
	Address            ContractAddress
	Network            Network
	Contract           *DeployedContract
	BytecodeComparison *BytecodeComparisonResult
	SuspiciousPatterns []SuspiciousPattern
	FunctionSelectors  []string
	StaticFindings     []analyzer.Finding
	ExploitHistory     *ExploitHistory
}

func (r *OnChainAnalysisResult) ToAnalysisResult() analyzer.AnalysisResult {
	return analyzer.AnalysisResult{
		Filepath: fmt.Sprintf("onchain://%s/%s", r.Network, r.Address),
		Findings: r.StaticFindings,
	}
}

func (r *OnChainAnalysisResult) HasCriticalIssues() bool {
	for _, f := range r.StaticFindings {
		if f.Severity == analyzer.Critical {
			return true
		}
	}
	return false
}

func inMemoryDetectors() []analyzer.Detector {
	return []analyzer.Detector{
		// detectors.NewReentrancyDetector(),
		// detectors.NewTxOriginDetector(),
		// detectors.NewUncheckedCallDetector(),
		// detectors.NewAccessControlDetector(),
	}
}

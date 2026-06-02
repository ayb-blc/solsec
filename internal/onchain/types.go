package onchain

import (
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type Network string

const (
	NetworkEthereum  Network = "ethereum"
	NetworkGoerli    Network = "goerli"
	NetworkSepolia   Network = "sepolia"
	NetworkPolygon   Network = "polygon"
	NetworkArbitrum  Network = "arbitrum"
	NetworkOptimism  Network = "optimism"
	NetworkBSC       Network = "bsc"
	NetworkAvalanche Network = "avalanche"
	NetworkBase      Network = "base"
)

var EtherscanBaseURL = map[Network]string{
	NetworkEthereum:  "https://api.etherscan.io/api",
	NetworkGoerli:    "https://api-goerli.etherscan.io/api",
	NetworkSepolia:   "https://api-sepolia.etherscan.io/api",
	NetworkPolygon:   "https://api.polygonscan.com/api",
	NetworkArbitrum:  "https://api.arbiscan.io/api",
	NetworkOptimism:  "https://api-optimistic.etherscan.io/api",
	NetworkBSC:       "https://api.bscscan.com/api",
	NetworkAvalanche: "https://api.snowtrace.io/api",
	NetworkBase:      "https://api.basescan.org/api",
}

// ContractAddress EVM contract adresi (checksum'siz, lower-case).
type ContractAddress string

type DeployedContract struct {
	// Address contract adresi
	Address ContractAddress

	Network Network

	// Bytecode runtime bytecode (0x prefix'siz)
	Bytecode string

	// CreationBytecode deployment bytecode
	CreationBytecode string

	IsVerified bool

	VerifiedSource *VerifiedSource

	// DeploymentInfo deployment bilgisi
	DeploymentInfo *DeploymentInfo

	// Balance ETH balance (wei cinsinden)
	Balance string

	TransactionCount uint64
}

type VerifiedSource struct {
	ContractName string

	CompilerVersion string

	// OptimizationUsed optimizasyon aktif miydi?
	OptimizationUsed bool

	OptimizationRuns int

	SourceCode string

	// ABI contract ABI (JSON string)
	ABI string

	ConstructorArguments string

	// EVMVersion hedef EVM versiyonu
	EVMVersion string

	LicenseType string

	SourceFiles map[string]string

	VerifiedAt time.Time
}

type DeploymentInfo struct {
	// DeployerAddress deploy eden adres
	DeployerAddress string

	// DeploymentTxHash deployment transaction hash'i
	DeploymentTxHash string

	DeploymentBlock uint64

	DeploymentTimestamp time.Time
}

type BytecodeComparisonResult struct {
	Address ContractAddress

	Network Network

	Match bool

	MatchType MatchType

	// OnChainBytecodeHash on-chain bytecode hash'i
	OnChainBytecodeHash string

	// LocalBytecodeHash lokal derleme bytecode hash'i
	LocalBytecodeHash string

	Differences []BytecodeDiff

	SuspiciousPatterns []SuspiciousPattern

	MetadataMatch bool

	// SwarmHash IPFS/Swarm metadata hash
	SwarmHash string
}

type MatchType string

const (
	MatchExact      MatchType = "exact"
	MatchPartial    MatchType = "partial"
	MatchNoSource   MatchType = "no_source"
	MatchMismatch   MatchType = "mismatch"
	MatchUnverified MatchType = "unverified"
)

type BytecodeDiff struct {
	Offset int

	// OnChainBytes on-chain bytecode
	OnChainBytes []byte

	// LocalBytes lokal bytecode
	LocalBytes []byte

	Description string
}

type SuspiciousPattern struct {
	Name string

	Description string

	// Offset bytecode'daki pozisyon
	Offset int

	// Opcode ilgili opcode
	Opcode string

	// Severity risk seviyesi
	Severity analyzer.Severity

	ByteSequence string
}

type OnChainFinding struct {
	analyzer.Finding

	// Address ilgili contract adresi
	Address ContractAddress

	Network Network

	// TxHash ilgili transaction hash (varsa)
	TxHash string

	BlockNumber uint64
}

type TransactionAnalysis struct {
	// TxHash transaction hash'i
	TxHash string

	From string

	// To hedef adres
	To string

	Value string

	// Input calldata
	Input string

	IsAttack bool

	AttackType string

	RelatedFindings []string
}

type ExploitHistory struct {
	// Address contract adresi
	Address ContractAddress

	// KnownExploits bilinen exploit'ler
	KnownExploits []KnownExploit

	SuspiciousTransactions []TransactionAnalysis
}

type KnownExploit struct {
	// Date exploit tarihi
	Date time.Time

	Description string

	// LossAmount kaybedilen miktar (USD)
	LossAmount float64

	// TxHash exploit transaction hash'i
	TxHash string

	VulnerabilityType string

	Reference string
}

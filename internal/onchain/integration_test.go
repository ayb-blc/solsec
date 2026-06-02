package onchain_test

import (
	"os"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/onchain"
)

func TestIntegration_FetchUSDC(t *testing.T) {
	apiKey := os.Getenv("ETHERSCAN_API_KEY")
	if apiKey == "" {
		t.Skip("ETHERSCAN_API_KEY not set")
	}

	client := onchain.NewEtherscanClient(apiKey, onchain.NetworkEthereum)
	fetcher := onchain.NewSourceFetcher(client)

	addr := onchain.ContractAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

	fetched, err := fetcher.Fetch(addr)
	if err != nil {
		t.Fatalf("Fetch USDC: %v", err)
	}
	defer fetched.Close()

	if fetched.ContractName == "" {
		t.Error("expected contract name")
	}
	if len(fetched.Files) == 0 {
		t.Error("expected at least one source file")
	}

	t.Logf("Contract: %s", fetched.ContractName)
	t.Logf("Files: %d", len(fetched.Files))
	t.Logf("IsProxy: %v", fetched.IsProxy)
	if fetched.IsProxy {
		t.Logf("ProxyKind: %s", fetched.ProxyKind)
		t.Logf("Implementation: %s", fetched.Implementation)
	}

	// Normal analyzer pipeline ile scan et
	a := analyzer.New(detectors.DefaultDetectors(), analyzer.Config{Workers: 2})
	results, err := a.ScanDirectory(fetched.TempDir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}
	t.Logf("Findings: %d", total)
}

func TestIntegration_ProxyDetection_Transparent(t *testing.T) {
	apiKey := os.Getenv("ETHERSCAN_API_KEY")
	if apiKey == "" {
		t.Skip("ETHERSCAN_API_KEY not set")
	}

	client := onchain.NewEtherscanClient(apiKey, onchain.NetworkEthereum)
	pd := onchain.NewProxyDetector(client)

	// USDC proxy (TransparentUpgradeableProxy)
	addr := onchain.ContractAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	source, err := client.GetSourceCode(addr)
	if err != nil {
		t.Fatalf("GetSourceCode: %v", err)
	}

	bytecode, _ := client.GetBytecode(addr)
	info, err := pd.Detect(addr, source, bytecode)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if info == nil {
		t.Fatal("USDC should be detected as proxy")
	}

	t.Logf("Kind: %s", info.Kind)
	t.Logf("Implementation: %s", info.ImplementationAddress)
	t.Logf("IsUpgradeable: %v", info.IsUpgradeable)
}

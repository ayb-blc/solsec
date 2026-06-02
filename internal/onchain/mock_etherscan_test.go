package onchain

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

func TestMockEtherscan_SourceFetcher(t *testing.T) {
	mock := NewMockEtherscan()
	defer mock.Close()

	fetcher := NewSourceFetcher(mock.Client())
	fetched, err := fetcher.Fetch("0x0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer fetched.Close()

	if fetched.ContractName != "MockVault" {
		t.Fatalf("contract name = %q", fetched.ContractName)
	}
	if len(fetched.Files) == 0 {
		t.Fatal("expected source files")
	}
}

func TestMockEtherscan_OnChainScanner(t *testing.T) {
	mock := NewMockEtherscan()
	defer mock.Close()

	scanner := NewOnChainScannerWithClient(mock.Client())
	a := analyzer.New(detectors.DefaultDetectors(), analyzer.Config{Workers: 1})

	result, err := scanner.Scan("0x0000000000000000000000000000000000000001", a)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.ContractName != "MockVault" {
		t.Fatalf("contract name = %q", result.ContractName)
	}
	if len(result.AnalysisResults) == 0 {
		t.Fatal("expected analyzer results")
	}
}

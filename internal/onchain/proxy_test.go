package onchain_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/onchain"
)

func TestProxyDetector_MinimalProxy(t *testing.T) {
	detector := onchain.NewProxyDetector(nil)
	bytecode := "363d3d373d3d3d363d73" +
		"1234567890abcdef1234567890abcdef12345678" +
		"5af43d82803e903d91602b57fd5bf3"

	info, err := detector.Detect("0x0000000000000000000000000000000000000001", nil, bytecode)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if info == nil {
		t.Fatal("expected minimal proxy to be detected")
	}
	if info.Kind != onchain.ProxyMinimal {
		t.Fatalf("kind = %s, want %s", info.Kind, onchain.ProxyMinimal)
	}
	if info.ImplementationAddress != "0x1234567890abcdef1234567890abcdef12345678" {
		t.Fatalf("implementation = %s", info.ImplementationAddress)
	}
}

func TestProxyDetector_SourceHeuristic(t *testing.T) {
	detector := onchain.NewProxyDetector(nil)
	source := &onchain.VerifiedSource{
		ContractName: "TransparentUpgradeableProxy",
		SourceCode:   "contract TransparentUpgradeableProxy { function upgradeTo(address impl) external {} }",
	}

	info, err := detector.Detect("0x0000000000000000000000000000000000000001", source, "")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if info == nil {
		t.Fatal("expected source heuristic to detect proxy")
	}
	if info.Kind != onchain.ProxyTransparent {
		t.Fatalf("kind = %s, want %s", info.Kind, onchain.ProxyTransparent)
	}
}

package onchain_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/onchain"
)

func TestBytecodeAnalyzer_ExactMatch(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()
	bytecode := "6080604052348015600f57600080fd5b50"

	result := ba.Compare(bytecode, bytecode)
	if !result.Match {
		t.Error("identical bytecodes should match")
	}
	if result.MatchType != onchain.MatchExact {
		t.Errorf("match type = %v, want MatchExact", result.MatchType)
	}
}

func TestBytecodeAnalyzer_MetadataStrip(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()

	logic := "6080604052348015600f57600080fd5b50"
	metaA := "a265627a7a72305820" + "aa" + "0029"
	metaB := "a265627a7a72305820" + "bb" + "0029"

	bytecodeA := logic + metaA
	bytecodeB := logic + metaB

	result := ba.Compare(bytecodeA, bytecodeB)
	if !result.Match {
		t.Error("bytecodes with same logic but different metadata should match (partial)")
	}
	if result.MatchType != onchain.MatchPartial {
		t.Errorf("match type = %v, want MatchPartial", result.MatchType)
	}
	if result.MetadataMatch {
		t.Error("different metadata should not match")
	}
}

func TestBytecodeAnalyzer_Mismatch(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()
	a := "6080604052"
	b := "6080604053"

	result := ba.Compare(a, b)
	if result.Match {
		t.Error("different bytecodes should not match")
	}
	if result.MatchType != onchain.MatchMismatch {
		t.Errorf("match type = %v, want MatchMismatch", result.MatchType)
	}
	if len(result.Differences) == 0 {
		t.Error("expected differences to be reported")
	}
}

func TestBytecodeAnalyzer_EmptyOnChain(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()
	result := ba.Compare("", "6080604052")
	if result.MatchType != onchain.MatchNoSource {
		t.Errorf("match type = %v, want MatchNoSource", result.MatchType)
	}
}

func TestBytecodeAnalyzer_SuspiciousPatterns(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()

	bytecode := "6080604052" + "32" + "ff" + "5b00"

	patterns := ba.AnalyzePatterns(bytecode)

	foundSelfDestruct := false
	foundOrigin := false
	for _, p := range patterns {
		switch p.Opcode {
		case "SELFDESTRUCT":
			foundSelfDestruct = true
		case "ORIGIN":
			foundOrigin = true
		}
	}

	if !foundSelfDestruct {
		t.Error("expected SELFDESTRUCT pattern to be detected")
	}
	if !foundOrigin {
		t.Error("expected ORIGIN (tx.origin) pattern to be detected")
	}
}

func TestBytecodeAnalyzer_FunctionSelectors(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()

	// PUSH4 + selector + DUP1 pattern
	// withdraw() = 0x3ccfd60b
	bytecode := "6080604052" +
		"63" + "3ccfd60b" + "80" + // PUSH4 withdraw DUP1
		"6080604052"

	selectors := ba.ExtractFunctionSelectors(bytecode)
	if len(selectors) == 0 {
		t.Error("expected function selectors to be extracted")
	}

	found := false
	for _, sel := range selectors {
		if sel == "0x3ccfd60b" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 0x3ccfd60b in selectors, got %v", selectors)
	}
}

func TestBytecodeAnalyzer_DecompileBasic(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()

	// PUSH1 0x80 PUSH1 0x40 MSTORE STOP
	bytecode := "6080604052 00"
	bytecode = "608060405200"

	entries := ba.DecompileBasic(bytecode)
	if len(entries) == 0 {
		t.Fatal("expected decompiled entries")
	}

	if entries[0].Name != "PUSH1" {
		t.Errorf("first opcode = %q, want PUSH1", entries[0].Name)
	}
}

func TestNetworkURLs(t *testing.T) {
	networks := []onchain.Network{
		onchain.NetworkEthereum,
		onchain.NetworkPolygon,
		onchain.NetworkArbitrum,
		onchain.NetworkOptimism,
		onchain.NetworkBSC,
	}

	for _, net := range networks {
		url, ok := onchain.EtherscanBaseURL[net]
		if !ok {
			t.Errorf("no URL for network %s", net)
		}
		if url == "" {
			t.Errorf("empty URL for network %s", net)
		}
	}
}

func TestKnownExploitDB_Lookup_Unknown(t *testing.T) {
	db := onchain.NewKnownExploitDB()
	history := db.Lookup("0x0000000000000000000000000000000000000001")
	if history == nil {
		t.Fatal("lookup should return empty history, not nil")
	}
	if len(history.KnownExploits) != 0 {
		t.Error("unknown address should have no exploits")
	}
}

func TestGlobalFunctionID_HashLength(t *testing.T) {
	ba := onchain.NewBytecodeAnalyzer()
	_ = ba

	b1 := "6080604052"
	b2 := "6080604052"

	r1 := ba.Compare(b1, b2)
	r2 := ba.Compare(b1, b2)

	if r1.OnChainBytecodeHash != r2.OnChainBytecodeHash {
		t.Error("bytecode hash should be deterministic")
	}
	if len(r1.OnChainBytecodeHash) != 64 {
		t.Errorf("hash length = %d, want 64", len(r1.OnChainBytecodeHash))
	}
}

func TestOnChainPipelineOpts_Default(t *testing.T) {
	opts := onchain.DefaultOnChainPipelineOpts("test-key", onchain.NetworkEthereum)
	if opts.APIKey != "test-key" {
		t.Errorf("api key = %q, want test-key", opts.APIKey)
	}
	if opts.Network != onchain.NetworkEthereum {
		t.Errorf("network = %v, want ethereum", opts.Network)
	}
	if !opts.AnalyzeBytecode {
		t.Error("AnalyzeBytecode should be true by default")
	}
	if !opts.RunStaticAnalysis {
		t.Error("RunStaticAnalysis should be true by default")
	}
}

func TestEtherscanClient_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	apiKey := getTestAPIKey(t)
	client := onchain.NewEtherscanClient(apiKey, onchain.NetworkEthereum)

	addr := onchain.ContractAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

	bytecode, err := client.GetBytecode(addr)
	if err != nil {
		t.Fatalf("GetBytecode: %v", err)
	}
	if bytecode == "" {
		t.Error("expected non-empty bytecode for USDC")
	}
	if len(bytecode) < 100 {
		t.Errorf("bytecode too short: %d chars", len(bytecode))
	}
}

func getTestAPIKey(t *testing.T) string {
	t.Helper()
	key := "" // os.Getenv("ETHERSCAN_API_KEY")
	if key == "" {
		t.Skip("ETHERSCAN_API_KEY not set — skipping integration test")
	}
	return key
}

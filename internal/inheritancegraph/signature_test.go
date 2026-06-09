// internal/inheritancegraph/signature_test.go

package inheritancegraph_test

import (
	"encoding/hex"
	"testing"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

func TestSignatureResolver_Parse_SimpleFunction(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	tests := []struct {
		input         string
		wantName      string
		wantCanonical string
	}{
		{
			"function transfer(address to, uint256 amount) external",
			"transfer",
			"transfer(address,uint256)",
		},
		{
			"function setFee(uint fee_) external onlyOwner",
			"setFee",
			"setFee(uint256)", // uint normalizes to uint256.
		},
		{
			"function approve(address spender, uint value) external returns (bool)",
			"approve",
			"approve(address,uint256)",
		},
		{
			"function getData() external view returns (bytes memory)",
			"getData",
			"getData()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantCanonical, func(t *testing.T) {
			got := r.Parse(tt.input)
			if got == nil {
				t.Fatalf("Parse(%q) = nil", tt.input)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Canonical != tt.wantCanonical {
				t.Errorf("Canonical = %q, want %q", got.Canonical, tt.wantCanonical)
			}
		})
	}
}

func TestSignatureResolver_TypeNormalization(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	cases := []struct{ input, want string }{
		{"uint", "uint256"},
		{"int", "int256"},
		{"byte", "bytes1"},
		{"uint256", "uint256"},
		{"uint128", "uint128"},
		{"address payable", "address"},
		{"uint[]", "uint256[]"},
		{"uint[3]", "uint256[3]"},
		{"bytes calldata", "bytes"},
		{"uint256 memory", "uint256"},
	}

	for _, tc := range cases {
		got := r.NormalizeType(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeType(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSignatureResolver_SelectorsMatch(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	// These should all produce the same canonical form and selector
	equivalent := []string{
		"function setFee(uint fee_) external",
		"function setFee(uint256 fee_) external",
		"function setFee(uint256) external",
		"setFee(uint256)",
		"setFee(uint)",
	}

	first := r.Parse(equivalent[0])
	if first == nil {
		t.Fatal("Parse failed")
	}

	for _, sig := range equivalent[1:] {
		if !r.SelectorsMatch(equivalent[0], sig) {
			t.Errorf("SelectorsMatch(%q, %q) = false, want true", equivalent[0], sig)
		}
		other := r.Parse(sig)
		if other.Selector != first.Selector {
			t.Errorf("selector mismatch: %q vs %q", equivalent[0], sig)
		}
	}
}

func TestSignatureResolver_KnownABISelector(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()
	got := r.Parse("transfer(address,uint256)")
	if got == nil {
		t.Fatal("Parse failed")
	}
	if hex.EncodeToString(got.Selector[:]) != "a9059cbb" {
		t.Fatalf("selector = %x, want a9059cbb", got.Selector)
	}
}

func TestSignatureResolver_SelectorsDistinct(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	// Different functions must have different selectors
	pairs := [][2]string{
		{"setFee(uint256)", "setFee(address)"},
		{"transfer(address,uint256)", "transferFrom(address,address,uint256)"},
		{"pause()", "unpause()"},
	}

	for _, pair := range pairs {
		if r.SelectorsMatch(pair[0], pair[1]) {
			t.Errorf("SelectorsMatch(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

func TestSignatureResolver_TupleParam(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	sig := "function execute((address target, uint256 value, bytes data) calldata call) external"
	got := r.Parse(sig)
	if got == nil {
		t.Fatal("Parse returned nil")
	}
	if got.Canonical != "execute((address,uint256,bytes))" {
		t.Errorf("Canonical = %q, want execute((address,uint256,bytes))", got.Canonical)
	}
}

func TestSignatureResolver_MultilineSignature(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	// Simulates what collectFunctionSignature produces
	multiline := "function initialize( address pool, address treasury, address underlyingAsset, uint8 decimals, string calldata name, string calldata symbol, bytes calldata params ) external override initializer {"

	got := r.Parse(multiline)
	if got == nil {
		t.Fatal("Parse returned nil on multi-line signature")
	}
	want := "initialize(address,address,address,uint8,string,string,bytes)"
	if got.Canonical != want {
		t.Errorf("Canonical = %q\n  want    = %q", got.Canonical, want)
	}
}

func TestSignatureResolver_OverloadDistinction(t *testing.T) {
	r := inheritancegraph.NewSignatureResolver()

	// Different overloads must have different selectors
	a := r.Parse("function mint(address to) external")
	b := r.Parse("function mint(address to, uint256 amount) external")

	if a.Selector == b.Selector {
		t.Error("mint(address) and mint(address,uint256) must have different selectors")
	}
	if a.Canonical == b.Canonical {
		t.Error("canonical forms must differ for different overloads")
	}
}

func TestGraph_EnrichFunctions_SelectorPopulated(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.sol", `
contract A {
    function setFee(uint fee_) external virtual {}
}`)
	writeFile(t, dir, "B.sol", `
import "./A.sol";
contract B is A {
    // uses uint256, same function as parent's setFee(uint)
    function setFee(uint256 fee_) external override {}
}`)

	b := inheritancegraph.NewBuilder(dir)
	g, _ := b.BuildFromFiles([]string{
		dir + "/A.sol",
		dir + "/B.sol",
	})
	g.EnrichFunctions()

	nodeA := g.FindOne("A")
	nodeB := g.FindOne("B")

	fnA := nodeA.Functions["setFee"]
	fnB := nodeB.Functions["setFee"]

	if fnA == nil || fnB == nil {
		t.Fatal("functions not found")
	}
	if fnA.Canonical != "setFee(uint256)" {
		t.Errorf("A.setFee canonical = %q, want setFee(uint256)", fnA.Canonical)
	}
	if fnA.Selector != fnB.Selector {
		t.Errorf("A.setFee and B.setFee must have same selector (uint == uint256)")
	}
}

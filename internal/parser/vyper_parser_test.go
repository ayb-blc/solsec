package parser_test

import (
	"os"
	"testing"

	"github.com/ayb-blc/solsec/internal/parser"
)

const vyperSampleVulnerable = `
# @version 0.3.10

balances: HashMap[address, uint256]

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    raw_call(msg.sender, b"", value=amount)   # external call
    self.balances[msg.sender] -= amount        # state update after call — CEI violation
`

const vyperSampleSafe = `
# @version 0.3.10

balances: HashMap[address, uint256]

@external
@nonreentrant("lock")
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    self.balances[msg.sender] -= amount        # state update BEFORE call — CEI correct
    raw_call(msg.sender, b"", value=amount)
`

func TestVyperParser_Language(t *testing.T) {
	p := parser.NewVyperParser("")
	if p.Language() != parser.LanguageVyper {
		t.Errorf("expected LanguageVyper, got %v", p.Language())
	}
}

func TestVyperParser_CanParse(t *testing.T) {
	p := parser.NewVyperParser("")
	cases := []struct {
		path string
		want bool
	}{
		{"Token.vy", true},
		{"Vault.sol", false},
		{"readme.md", false},
		{"/contracts/ERC20.vy", true},
	}
	for _, tc := range cases {
		got := p.CanParse(tc.path)
		if got != tc.want {
			t.Errorf("CanParse(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestVyperParser_Parse_Vulnerable(t *testing.T) {
	if !vyperAvailable() {
		t.Skip("vyper not available")
	}

	f := writeTempVy(t, vyperSampleVulnerable)
	p := parser.NewVyperParser("")
	ast, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if ast.Language != parser.LanguageVyper {
		t.Errorf("expected LanguageVyper")
	}
	if len(ast.Contracts) == 0 {
		t.Fatal("expected at least one contract/module")
	}

	contract := ast.Contracts[0]

	var withdrawFn *parser.UnifiedFunction
	for _, fn := range contract.Functions {
		if fn.Name == "withdraw" {
			withdrawFn = fn
			break
		}
	}
	if withdrawFn == nil {
		t.Fatal("withdraw function not found")
	}

	hasExtCall := false
	for _, stmt := range withdrawFn.Body {
		if stmt.ContainsExternalCall {
			hasExtCall = true
			break
		}
	}
	if !hasExtCall {
		t.Error("withdraw should contain external call (raw_call)")
	}
}

func TestVyperParser_Parse_Safe_Nonreentrant(t *testing.T) {
	if !vyperAvailable() {
		t.Skip("vyper not available")
	}

	f := writeTempVy(t, vyperSampleSafe)
	p := parser.NewVyperParser("")
	ast, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	contract := ast.Contracts[0]
	var withdrawFn *parser.UnifiedFunction
	for _, fn := range contract.Functions {
		if fn.Name == "withdraw" {
			withdrawFn = fn
			break
		}
	}
	if withdrawFn == nil {
		t.Fatal("withdraw function not found")
	}

	hasNonreentrant := false
	for _, mod := range withdrawFn.Modifiers {
		if mod == "nonreentrant" {
			hasNonreentrant = true
			break
		}
	}
	if !hasNonreentrant {
		t.Error("withdraw should have nonreentrant modifier from @nonreentrant decorator")
	}
}

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		path string
		want parser.Language
	}{
		{"Token.sol", parser.LanguageSolidity},
		{"Vault.vy", parser.LanguageVyper},
		{"readme.md", parser.LanguageUnknown},
		{"/a/b/c/ERC20.sol", parser.LanguageSolidity},
		{"/a/b/c/ERC20.vy", parser.LanguageVyper},
	}
	for _, tc := range cases {
		got := parser.DetectLanguage(tc.path)
		if got != tc.want {
			t.Errorf("DetectLanguage(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParserRegistry_ParserFor(t *testing.T) {
	r := parser.DefaultRegistry()

	cases := []struct {
		path     string
		wantLang parser.Language
		wantErr  bool
	}{
		{"Token.sol", parser.LanguageSolidity, false},
		{"Vault.vy", parser.LanguageVyper, false},
		{"readme.md", "", true},
	}

	for _, tc := range cases {
		p, err := r.ParserFor(tc.path)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParserFor(%q): expected error", tc.path)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParserFor(%q): unexpected error: %v", tc.path, err)
			continue
		}
		if p.Language() != tc.wantLang {
			t.Errorf("ParserFor(%q) language = %v, want %v",
				tc.path, p.Language(), tc.wantLang)
		}
	}
}

func TestInheritanceGraph_VyperNoInheritance(t *testing.T) {
	if !vyperAvailable() {
		t.Skip("vyper not available")
	}

	f := writeTempVy(t, vyperSampleSafe)
	p := parser.NewVyperParser("")
	ast, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, c := range ast.Contracts {
		if len(c.Parents) > 0 {
			t.Errorf("Vyper contract should have no parents, got %v", c.Parents)
		}
	}
}

func vyperAvailable() bool {
	return parser.NewVyperParser("").IsAvailable()
}

func writeTempVy(t *testing.T, source string) string {
	t.Helper()
	f, err := os.CreateTemp("", "solsec_test_*.vy")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(source)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

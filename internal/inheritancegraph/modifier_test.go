// internal/inheritancegraph/modifier_test.go

package inheritancegraph_test

import (
	"path/filepath"
	"testing"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

func TestModifierResolver_Resolve_SameFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vault.sol", `
pragma solidity ^0.8.0;
contract Vault {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setFee(uint256 f) external onlyOwner {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	vault := g.FindOne("Vault")
	fn := vault.Functions["setFee"]

	def := r.Resolve("onlyOwner", vault)
	if def == nil {
		t.Fatal("onlyOwner not resolved")
	}
	if def.Category != inheritancegraph.CategoryAccessControl {
		t.Errorf("category = %v, want access-control", def.Category)
	}
	if !r.HasAccessControl(fn) {
		t.Error("HasAccessControl = false, want true")
	}
}

func TestModifierResolver_Resolve_Inherited(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    // Uses onlyOwner from Base; not redefined here.
    function pause() external onlyOwner {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	child := g.FindOne("Child")
	fn := child.Functions["pause"]

	def := r.Resolve("onlyOwner", child)
	if def == nil {
		t.Fatal("onlyOwner not resolved from ancestor")
	}
	if def.Contract.Name != "Base" {
		t.Errorf("contract = %q, want Base", def.Contract.Name)
	}
	if !r.HasAccessControl(fn) {
		t.Error("inherited modifier should count as access control")
	}
}

func TestModifierResolver_WellKnown_NonReentrant(t *testing.T) {
	dir := t.TempDir()
	// nonReentrant is defined in an external OZ library, not in source.
	writeFile(t, dir, "Pool.sol", `
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Pool is ReentrancyGuard {
    function flashLoan(address receiver, uint256 amount) external nonReentrant {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	pool := g.FindOne("Pool")
	fn := pool.Functions["flashLoan"]

	def := r.Resolve("nonReentrant", pool)
	if def == nil {
		t.Fatal("nonReentrant not resolved from well-known registry")
	}
	if def.Category != inheritancegraph.CategoryReentrancyGuard {
		t.Errorf("category = %v, want reentrancy-guard", def.Category)
	}
	if !def.IsWellKnown {
		t.Error("IsWellKnown should be true for OZ modifier")
	}
	if !r.HasReentrancyGuard(fn) {
		t.Error("HasReentrancyGuard = false, want true")
	}
}

func TestModifierResolver_BodyClassification_ReentrancyGuard(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Guard.sol", `
contract Guard {
    bool private _locked;

    modifier noReentrancy() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw() external noReentrancy {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	guard := g.FindOne("Guard")
	fn := guard.Functions["withdraw"]

	def := r.Resolve("noReentrancy", guard)
	if def == nil {
		t.Fatal("noReentrancy not resolved")
	}
	if def.Category != inheritancegraph.CategoryReentrancyGuard {
		t.Errorf("body analysis: category = %v, want reentrancy-guard", def.Category)
	}
	if !r.HasReentrancyGuard(fn) {
		t.Error("HasReentrancyGuard = false for custom mutex")
	}
}

func TestModifierResolver_BodyClassification_RoleBasedAC(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Access.sol", `
contract Access {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    modifier onlyMinter() {
        require(hasRole(MINTER_ROLE, msg.sender), "not minter");
        _;
    }

    function mint(address to, uint256 amount) external onlyMinter {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	access := g.FindOne("Access")

	def := r.Resolve("onlyMinter", access)
	if def == nil {
		t.Fatal("onlyMinter not resolved")
	}
	if def.Category != inheritancegraph.CategoryAccessControl {
		t.Errorf("hasRole pattern: category = %v, want access-control", def.Category)
	}

	// Verify specific check is detected
	found := false
	for _, check := range def.Checks {
		if check.Kind == inheritancegraph.CheckMsgSenderHasRole {
			found = true
		}
	}
	if !found {
		t.Error("CheckMsgSenderHasRole not found in modifier checks")
	}
}

func TestModifierResolver_OverrideDroppedAC(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function pause() external virtual onlyOwner {}
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    // Dropped onlyOwner
    function pause() external override {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	child := g.FindOne("Child")
	base := g.FindOne("Base")

	childFn := child.Functions["pause"]
	parentFn := base.Functions["pause"]

	droppedDef, dropped := r.OverrideDroppedAccessControl(childFn, parentFn)
	if !dropped {
		t.Fatal("should detect dropped access control")
	}
	if droppedDef.Name != "onlyOwner" {
		t.Errorf("dropped modifier = %q, want onlyOwner", droppedDef.Name)
	}
}

func TestModifierResolver_NoFalsePositive_EquivalentAC(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner {}
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    // Different name, same category; should NOT be flagged.
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    function setFee(uint256 f) external override onlyAdmin {}
}`)

	g := buildGraph(t, dir)
	g.EnrichModifiers()
	r := inheritancegraph.NewModifierResolver(g)

	child := g.FindOne("Child")
	base := g.FindOne("Base")

	childFn := child.Functions["setFee"]
	parentFn := base.Functions["setFee"]

	_, dropped := r.OverrideDroppedAccessControl(childFn, parentFn)
	if dropped {
		// Child has onlyAdmin (access control); not a regression.
		t.Error("false positive: onlyAdmin is equivalent category to onlyOwner")
	}
}

func TestClassifyByName_Patterns(t *testing.T) {
	cases := []struct {
		name      string
		wantCat   inheritancegraph.ModifierCategory
		wantKnown bool
	}{
		{"onlyOwner", inheritancegraph.CategoryAccessControl, true},
		{"nonReentrant", inheritancegraph.CategoryReentrancyGuard, true},
		{"whenNotPaused", inheritancegraph.CategoryPauseCheck, true},
		{"initializer", inheritancegraph.CategoryInitializerOnce, true},
		{"onlyPoolAdmin", inheritancegraph.CategoryAccessControl, true},
		{"onlyCustomGuardian", inheritancegraph.CategoryAccessControl, true}, // "only" prefix
		{"lock", inheritancegraph.CategoryReentrancyGuard, true},
		{"randomModifier", inheritancegraph.CategoryUnknown, false},
	}

	for _, tc := range cases {
		got, known := inheritancegraph.ClassifyByName(tc.name)
		if got != tc.wantCat {
			t.Errorf("ClassifyByName(%q) category = %v, want %v", tc.name, got, tc.wantCat)
		}
		if known != tc.wantKnown {
			t.Errorf("ClassifyByName(%q) known = %v, want %v", tc.name, known, tc.wantKnown)
		}
	}
}

// buildGraph is a test helper that scans all .sol files in dir.
func buildGraph(t *testing.T, dir string) *inheritancegraph.Graph {
	t.Helper()
	files, err := filepath.Glob(dir + "/*.sol")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	g, err := inheritancegraph.NewBuilder(dir).BuildFromFiles(files)
	if err != nil {
		t.Fatalf("BuildFromFiles: %v", err)
	}
	return g
}

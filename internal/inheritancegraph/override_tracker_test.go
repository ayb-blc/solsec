// internal/inheritancegraph/override_tracker_test.go

package inheritancegraph_test

import (
	"path/filepath"
	"testing"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

// Chain construction.

func TestOverrideTracker_GetChain_ThreeLevels(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.sol", `
contract A {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner { fee = f; }
}`)
	writeFile(t, dir, "B.sol", `
import "./A.sol";
contract B is A {
    function setFee(uint256 f) external virtual override onlyOwner { fee = f * 2; }
}`)
	writeFile(t, dir, "C.sol", `
import "./B.sol";
contract C is B {
    // Drops onlyOwner!
    function setFee(uint256 f) external override { fee = f * 3; }
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	c := g.FindOne("C")
	chain := tracker.GetChain(c, "setFee")

	if chain.Depth() != 3 {
		t.Fatalf("chain depth = %d, want 3 (C, B, A)", chain.Depth())
	}
	if chain.Tip().Contract.Name != "C" {
		t.Errorf("tip = %q, want C", chain.Tip().Contract.Name)
	}
	if chain.Root().Contract.Name != "A" {
		t.Errorf("root = %q, want A", chain.Root().Contract.Name)
	}
	if !chain.Root().IsRoot {
		t.Error("root link should have IsRoot == true")
	}
}

func TestOverrideTracker_GetChain_NoOverride(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.sol", `
contract A {
    function foo() external {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	a := g.FindOne("A")
	chain := tracker.GetChain(a, "foo")

	// Depth 1 means no override chain, just the original definition.
	if chain.Depth() != 1 {
		t.Errorf("single definition: depth = %d, want 1", chain.Depth())
	}
}

// Modifier change detection.

func TestOverrideTracker_FindModifierChanges_Removed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function pause() external virtual onlyOwner { _paused = true; }
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    function pause() external override { _paused = true; }
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	child := g.FindOne("Child")
	chain := tracker.GetChain(child, "pause")
	changes := tracker.FindModifierChanges(chain)

	removed := filterByAction(changes, inheritancegraph.ModifierRemoved)
	if len(removed) == 0 {
		t.Fatal("expected onlyOwner to be in removed changes")
	}
	if removed[0].Name != "onlyOwner" {
		t.Errorf("removed modifier = %q, want onlyOwner", removed[0].Name)
	}
	if removed[0].Category != inheritancegraph.CategoryAccessControl {
		t.Errorf("category = %v, want access-control", removed[0].Category)
	}
}

func TestOverrideTracker_FindModifierChanges_Added(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    function flashLoan(address r, uint256 a) external virtual {}
}`)
	writeFile(t, dir, "Safe.sol", `
import "./Base.sol";
contract Safe is Base {
    // Adds nonReentrant as a security improvement.
    function flashLoan(address r, uint256 a) external override nonReentrant {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	safe := g.FindOne("Safe")
	chain := tracker.GetChain(safe, "flashLoan")
	changes := tracker.FindModifierChanges(chain)

	added := filterByAction(changes, inheritancegraph.ModifierAdded)
	if len(added) == 0 {
		t.Fatal("expected nonReentrant to be in added changes")
	}
	if added[0].Category != inheritancegraph.CategoryReentrancyGuard {
		t.Errorf("category = %v, want reentrancy-guard", added[0].Category)
	}
}

// Security regression detection.

func TestOverrideTracker_FirstAccessControlRegression_DirectChild(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setAdmin(address a) external virtual onlyOwner {}
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    function setAdmin(address a) external override {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	child := g.FindOne("Child")
	chain := tracker.GetChain(child, "setAdmin")

	link, def := tracker.FirstAccessControlRegression(chain)
	if link == nil {
		t.Fatal("expected regression to be detected")
	}
	if link.Contract.Name != "Child" {
		t.Errorf("regression at = %q, want Child", link.Contract.Name)
	}
	if def.Name != "onlyOwner" {
		t.Errorf("dropped modifier = %q, want onlyOwner", def.Name)
	}
	if link.SecurityDelta.AccessControlRemoved != true {
		t.Error("SecurityDelta.AccessControlRemoved should be true")
	}
}

func TestOverrideTracker_FirstAccessControlRegression_GrandChild(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.sol", `
contract A {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function upgrade(address impl) external virtual onlyOwner {}
}`)
	writeFile(t, dir, "B.sol", `
import "./A.sol";
// B preserves the modifier
contract B is A {
    function upgrade(address impl) external virtual override onlyOwner {}
}`)
	writeFile(t, dir, "C.sol", `
import "./B.sol";
// C drops it; regression here.
contract C is B {
    function upgrade(address impl) external override {}
}`)
	writeFile(t, dir, "D.sol", `
import "./C.sol";
// D also has no modifier; regression was already in C.
contract D is C {
    function upgrade(address impl) external override {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	d := g.FindOne("D")
	chain := tracker.GetChain(d, "upgrade")

	link, _ := tracker.FirstAccessControlRegression(chain)
	if link == nil {
		t.Fatal("expected regression in chain D -> C -> B -> A")
	}
	// Regression first happened at C, not D
	if link.Contract.Name != "C" {
		t.Errorf("first regression at = %q, want C", link.Contract.Name)
	}
}

func TestOverrideTracker_NoRegression_WhenACKept(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner {}
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    // Different name, same category; NOT a regression.
    function setFee(uint256 f) external override onlyAdmin {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	child := g.FindOne("Child")
	chain := tracker.GetChain(child, "setFee")

	link, _ := tracker.FirstAccessControlRegression(chain)
	if link != nil {
		t.Error("false positive: onlyAdmin provides same category as onlyOwner")
	}
}

// Project-level index.

func TestProjectOverrideIndex_FindAllRegressions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vault.sol", `
contract Vault {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner {}
    function pause() external virtual onlyOwner {}
}`)
	writeFile(t, dir, "MaliciousChild.sol", `
import "./Vault.sol";
contract MaliciousChild is Vault {
    // Drops onlyOwner from BOTH functions
    function setFee(uint256 f) external override {}
    function pause() external override {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	idx := inheritancegraph.BuildIndex(g, modRes)

	reports := idx.FindAllRegressions()
	if len(reports) != 2 {
		t.Errorf("regressions = %d, want 2 (setFee and pause)", len(reports))
	}
}

func TestProjectOverrideIndex_NoFalsePositives_OnSafeContracts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Safe.sol", `
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner {}
}
contract Child is Base {
    function setFee(uint256 f) external override onlyOwner {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	idx := inheritancegraph.BuildIndex(g, modRes)

	reports := idx.FindAllRegressions()
	if len(reports) != 0 {
		t.Errorf("false positives: %d regressions on safe contracts", len(reports))
	}
}

// AnyLinkHasReentrancyGuard.

func TestOverrideTracker_AnyLinkHasReentrancyGuard(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    function flash(address r) external virtual nonReentrant {}
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
// Child removes nonReentrant but base had it
contract Child is Base {
    function flash(address r) external override {}
}`)

	g, modRes := buildGraphWithModifiers(t, dir)
	tracker := inheritancegraph.NewOverrideTracker(g, modRes)

	child := g.FindOne("Child")
	chain := tracker.GetChain(child, "flash")

	if !tracker.AnyLinkHasReentrancyGuard(chain) {
		t.Error("base has nonReentrant; AnyLinkHasReentrancyGuard should be true")
	}
}

// Test helpers.

func buildGraphWithModifiers(
	t *testing.T,
	dir string,
) (*inheritancegraph.Graph, *inheritancegraph.ModifierResolver) {
	t.Helper()
	files, err := filepath.Glob(dir + "/*.sol")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	g, err := inheritancegraph.NewBuilder(dir).BuildFromFiles(files)
	if err != nil {
		t.Fatalf("BuildFromFiles: %v", err)
	}
	g.EnrichFunctions()
	g.EnrichModifiers()
	return g, inheritancegraph.NewModifierResolver(g)
}

func filterByAction(
	changes []inheritancegraph.ModifierChange,
	action inheritancegraph.ChangeAction,
) []inheritancegraph.ModifierChange {
	var out []inheritancegraph.ModifierChange
	for _, c := range changes {
		if c.Action == action {
			out = append(out, c)
		}
	}
	return out
}

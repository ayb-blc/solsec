// internal/inheritancegraph/graph_test.go

package inheritancegraph_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

func TestGraph_BuildFromFiles_SimpleInheritance(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, "Base.sol", `
pragma solidity ^0.8.0;
contract Base {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 fee_) external virtual onlyOwner { fee = fee_; }
}`)
	writeFile(t, dir, "Child.sol", `
pragma solidity ^0.8.0;
import "./Base.sol";
contract Child is Base {
    function setFee(uint256 fee_) external override { fee = fee_; }
}`)

	builder := inheritancegraph.NewBuilder(dir)
	files := []string{
		filepath.Join(dir, "Base.sol"),
		filepath.Join(dir, "Child.sol"),
	}
	g, err := builder.BuildFromFiles(files)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if g.Size() != 2 {
		t.Errorf("size = %d, want 2", g.Size())
	}

	child := g.FindOne("Child")
	if child == nil {
		t.Fatal("Child not found in graph")
	}
	if len(child.Parents) != 1 {
		t.Fatalf("Child.Parents = %d, want 1", len(child.Parents))
	}
	if child.Parents[0].Name != "Base" {
		t.Errorf("Child.Parents[0] = %q, want Base", child.Parents[0].Name)
	}

	base := g.FindOne("Base")
	if len(base.Children) != 1 || base.Children[0].Name != "Child" {
		t.Errorf("Base.Children incorrect")
	}
}

func TestGraph_GetAncestors_MultiLevel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "A.sol", `contract A {}`)
	writeFile(t, dir, "B.sol", `import "./A.sol"; contract B is A {}`)
	writeFile(t, dir, "C.sol", `import "./B.sol"; contract C is B {}`)

	g, _ := inheritancegraph.NewBuilder(dir).BuildFromFiles([]string{
		filepath.Join(dir, "A.sol"),
		filepath.Join(dir, "B.sol"),
		filepath.Join(dir, "C.sol"),
	})

	c := g.FindOne("C")
	ancestors := g.GetAncestors(c)

	names := contractNames(ancestors)
	if !contains(names, "B") || !contains(names, "A") {
		t.Errorf("GetAncestors(C) = %v, want [B, A]", names)
	}
}

func TestGraph_OverrideDroppedAccessControl_Detected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    modifier onlyOwner() { _; }
    function pause() external virtual onlyOwner { _paused = true; }
}`)
	writeFile(t, dir, "Child.sol", `
import "./Base.sol";
contract Child is Base {
    function pause() external override { _paused = true; }
}`)

	g, _ := inheritancegraph.NewBuilder(dir).BuildFromFiles([]string{
		filepath.Join(dir, "Base.sol"),
		filepath.Join(dir, "Child.sol"),
	})

	child := g.FindOne("Child")
	parentFn, parentContract, dropped := g.OverrideDroppedAccessControl(child, "pause")

	if !dropped {
		t.Fatal("expected access control regression to be detected")
	}
	if parentContract.Name != "Base" {
		t.Errorf("parentContract = %q, want Base", parentContract.Name)
	}
	if parentFn.Name != "pause" {
		t.Errorf("parentFn = %q, want pause", parentFn.Name)
	}
}

func TestGraph_InheritsFrom(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Ownable.sol", `contract OwnableUpgradeable {}`)
	writeFile(t, dir, "Vault.sol", `
import "./Ownable.sol";
contract Vault is OwnableUpgradeable {}`)

	g, _ := inheritancegraph.NewBuilder(dir).BuildFromFiles([]string{
		filepath.Join(dir, "Ownable.sol"),
		filepath.Join(dir, "Vault.sol"),
	})

	vault := g.FindOne("Vault")
	if !g.InheritsFrom(vault, "OwnableUpgradeable") {
		t.Error("Vault should inherit OwnableUpgradeable")
	}
	if g.InheritsFrom(vault, "NonExistent") {
		t.Error("false positive on InheritsFrom")
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
}

func contractNames(nodes []*inheritancegraph.ContractNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Name
	}
	return out
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

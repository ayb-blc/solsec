package intercontract_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ayb-blc/solsec/internal/intercontract"
	"github.com/ayb-blc/solsec/internal/parser"
)

const vaultContract = `
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract Vault {
    IERC20 public token;
    IPriceOracle public oracle;
    mapping(address => uint256) public deposits;

    constructor(address _token, address _oracle) {
        token = IERC20(_token);
        oracle = IPriceOracle(_oracle);
    }

    function deposit(uint256 amount) external {
        token.transfer(address(this), amount);
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        uint256 price = oracle.getPrice();
        uint256 value = amount * price;
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, value);
    }

    function emergencyWithdraw() external {
        uint256 bal = deposits[msg.sender];
        deposits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
    }
}`

const tokenContract = `
pragma solidity ^0.8.0;

contract SimpleToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}`

const oracleContract = `
pragma solidity ^0.8.0;

contract PriceOracle {
    uint256 private price;
    address public owner;

    function setPrice(uint256 _price) external {
        price = _price;
    }

    function getPrice() external view returns (uint256) {
        return price;
    }
}`

func setupTestProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	files := map[string]string{
		"Vault.sol":       vaultContract,
		"Token.sol":       tokenContract,
		"PriceOracle.sol": oracleContract,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestProjectLoader_LoadsAllFiles(t *testing.T) {
	dir := setupTestProject(t)
	loader := intercontract.NewProjectLoader(parser.DefaultRegistry())
	project, err := loader.LoadProject(dir)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}

	if len(project.Files) != 3 {
		t.Errorf("expected 3 files, got %d", len(project.Files))
	}
}

func TestProjectLoader_ContractIndex(t *testing.T) {
	dir := setupTestProject(t)
	loader := intercontract.NewProjectLoader(parser.DefaultRegistry())
	project, err := loader.LoadProject(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"Vault", "SimpleToken", "PriceOracle"} {
		if _, ok := project.ContractIndex[name]; !ok {
			t.Errorf("contract %q not found in index", name)
		}
	}
}

func TestCrossContractGraphBuilder_BuildsNodes(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	dir := setupTestProject(t)
	loader := intercontract.NewProjectLoader(parser.DefaultRegistry())
	project, err := loader.LoadProject(dir)
	if err != nil {
		t.Fatal(err)
	}

	builder := intercontract.NewCrossContractGraphBuilder(project)
	graph := builder.Build()

	if len(graph.Nodes) == 0 {
		t.Error("expected nodes in cross-contract call graph")
	}

	withdrawID := intercontract.NewGlobalFunctionID("Vault", "withdraw")
	if _, ok := graph.Nodes[withdrawID]; !ok {
		t.Error("Vault.withdraw not found in graph")
	}
}

func TestCrossContractGraphBuilder_DetectsExternalCalls(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	dir := setupTestProject(t)
	loader := intercontract.NewProjectLoader(parser.DefaultRegistry())
	project, _ := loader.LoadProject(dir)

	builder := intercontract.NewCrossContractGraphBuilder(project)
	graph := builder.Build()

	withdrawID := intercontract.NewGlobalFunctionID("Vault", "withdraw")
	node, ok := graph.Nodes[withdrawID]
	if !ok {
		t.Skip("Vault.withdraw not in graph")
	}

	if !node.HasExternalCall && !node.TransitiveExternalCall {
		t.Error("Vault.withdraw should have external call (calls oracle.getPrice)")
	}
}

func TestCrossContractGraphBuilder_EntryPoints(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	dir := setupTestProject(t)
	loader := intercontract.NewProjectLoader(parser.DefaultRegistry())
	project, _ := loader.LoadProject(dir)

	builder := intercontract.NewCrossContractGraphBuilder(project)
	graph := builder.Build()

	if len(graph.EntryPoints) == 0 {
		t.Error("expected entry points (public/external functions)")
	}

	for _, ep := range graph.EntryPoints {
		if ep.Visibility != parser.VisibilityExternal &&
			ep.Visibility != parser.VisibilityPublic {
			t.Errorf("entry point %s has visibility %s", ep.ID, ep.Visibility)
		}
	}
}

func TestInterContractPipeline_Analyze(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	dir := setupTestProject(t)
	opts := intercontract.DefaultPipelineOptions()
	pipeline := intercontract.NewInterContractPipeline(parser.DefaultRegistry(), opts)

	result, err := pipeline.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.Stats.FilesAnalyzed == 0 {
		t.Error("no files analyzed")
	}
	if result.Stats.ContractsFound == 0 {
		t.Error("no contracts found")
	}

	t.Logf("Stats: files=%d contracts=%d functions=%d edges=%d findings=%d",
		result.Stats.FilesAnalyzed,
		result.Stats.ContractsFound,
		result.Stats.FunctionsAnalyzed,
		result.Stats.CrossContractEdges,
		len(result.Findings),
	)
}

func TestInterContractPipeline_ToAnalysisResults(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	dir := setupTestProject(t)
	opts := intercontract.DefaultPipelineOptions()
	pipeline := intercontract.NewInterContractPipeline(parser.DefaultRegistry(), opts)
	result, _ := pipeline.Analyze(dir)

	results := result.ToAnalysisResults()
	if len(result.Findings) > 0 && len(results) == 0 {
		t.Error("findings exist but ToAnalysisResults returned empty slice")
	}
}

func TestGlobalFunctionID(t *testing.T) {
	id := intercontract.NewGlobalFunctionID("Vault", "withdraw")

	if id.Contract() != "Vault" {
		t.Errorf("Contract() = %q, want Vault", id.Contract())
	}
	if id.Function() != "withdraw" {
		t.Errorf("Function() = %q, want withdraw", id.Function())
	}
	if id.String() != "Vault.withdraw" {
		t.Errorf("String() = %q, want Vault.withdraw", id.String())
	}
}

func solcAvailable() bool {
	return parser.NewSolcRunner("").IsAvailable()
}

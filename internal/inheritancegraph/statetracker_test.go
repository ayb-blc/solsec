// internal/inheritancegraph/statetracker_test.go

package inheritancegraph_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

// FunctionStateMap construction.

func TestStateTracker_BasicCEIViolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vault.sol", `
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        require(ok);
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	vault := g.FindOne("Vault")
	fn := vault.Functions["withdraw"]

	m := tracker.Analyze(fn, vault)

	if !m.HasWriteAfterCall() {
		t.Error("should detect write after external call")
	}

	violations := m.FindCEIViolations()
	if len(violations) == 0 {
		t.Fatal("expected CEI violation: balances write after .call")
	}
	v := violations[0]
	if v.ExternalCall.Method != "call" {
		t.Errorf("call method = %q, want call", v.ExternalCall.Method)
	}
	if v.WriteAfter.VarName != "balances" {
		t.Errorf("write var = %q, want balances", v.WriteAfter.VarName)
	}
}

func TestStateTracker_SafeCEI_NoViolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vault.sol", `
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;           // effect BEFORE interaction
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	vault := g.FindOne("Vault")
	fn := vault.Functions["withdraw"]
	m := tracker.Analyze(fn, vault)

	if m.HasWriteAfterCall() {
		t.Error("safe CEI: should not detect write after call")
	}
	if len(m.FindCEIViolations()) != 0 {
		t.Error("safe CEI: expected 0 violations")
	}
}

func TestStateTracker_WritesPrivilegedState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Ownable.sol", `
pragma solidity ^0.8.0;
contract Ownable {
    address public owner;

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	ownable := g.FindOne("Ownable")
	fn := ownable.Functions["transferOwnership"]
	m := tracker.Analyze(fn, ownable)

	isPriv, varName := m.WritesPrivilegedState()
	if !isPriv {
		t.Error("should detect write to privileged state (owner)")
	}
	if varName != "owner" {
		t.Errorf("privileged var = %q, want owner", varName)
	}
}

func TestStateTracker_InheritedStateVars(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Base.sol", `
contract Base {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
}`)
	writeFile(t, dir, "Token.sol", `
import "./Base.sol";
contract Token is Base {
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	token := g.FindOne("Token")
	fn := token.Functions["mint"]
	m := tracker.Analyze(fn, token)

	if !m.WritesTo("balances") {
		t.Error("should detect write to inherited balances")
	}
	if !m.WritesTo("totalSupply") {
		t.Error("should detect write to inherited totalSupply")
	}
}

func TestStateTracker_OrderedOps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Pool.sol", `
pragma solidity ^0.8.0;
contract Pool {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;  // WRITE (1)
        totalDeposits += msg.value;         // WRITE (2)
        emit Deposit(msg.sender, msg.value); // not a call
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	pool := g.FindOne("Pool")
	fn := pool.Functions["deposit"]
	m := tracker.Analyze(fn, pool)

	writeOps := filterOps(m.Ops, inheritancegraph.OpWrite)
	if len(writeOps) < 2 {
		t.Errorf("write ops = %d, want >= 2", len(writeOps))
	}
	if writeOps[0].Access.VarName != "deposits" {
		t.Errorf("first write = %q, want deposits", writeOps[0].Access.VarName)
	}
}

func TestStateTracker_MultipleCallsCEI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vulnerable.sol", `
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint256) public balances;
    address public feeRecipient;

    function withdrawWithFee(uint256 amount) external {
        uint256 fee = amount / 100;
        // First call transfers the fee.
        payable(feeRecipient).transfer(fee);
        // State write after first call
        balances[msg.sender] -= amount;
        // Second call
        (bool ok,) = msg.sender.call{value: amount - fee}("");
        require(ok);
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	v := g.FindOne("Vulnerable")
	fn := v.Functions["withdrawWithFee"]
	m := tracker.Analyze(fn, v)

	violations := m.FindCEIViolations()
	if len(violations) == 0 {
		t.Fatal("expected CEI violation: write after transfer")
	}
	// First violation: balances write after feeRecipient.transfer
	if violations[0].WriteAfter.VarName != "balances" {
		t.Errorf("violation write var = %q, want balances", violations[0].WriteAfter.VarName)
	}
}

// Integration: StateTracker improves reentrancy detector.

func TestStateTracker_NoFalsePositive_ViewOnlyFunction(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Pool.sol", `
pragma solidity ^0.8.0;
contract Pool {
    mapping(address => uint256) public balances;

    function getBalance(address who) external view returns (uint256) {
        return balances[who];
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	pool := g.FindOne("Pool")
	fn := pool.Functions["getBalance"]
	m := tracker.Analyze(fn, pool)

	if len(m.Writes) != 0 {
		t.Errorf("view function: writes = %d, want 0", len(m.Writes))
	}
	if len(m.ExtCalls) != 0 {
		t.Errorf("view function: ext calls = %d, want 0", len(m.ExtCalls))
	}
	if m.HasWriteAfterCall() {
		t.Error("view function: false positive CEI violation")
	}
}

func TestStateTracker_FlashLoanCallback_StateAroundCall(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Pool.sol", `
pragma solidity ^0.8.0;
contract Pool {
    uint256 public totalBorrowed;
    mapping(address => uint256) public reserves;

    function flashLoan(address receiver, uint256 amount) external {
        totalBorrowed += amount;
        IERC20(token).transfer(receiver, amount);
        IFlashBorrower(receiver).onFlashLoan(amount);
        totalBorrowed -= amount;
    }
}`)

	g, tracker := buildGraphWithTracker(t, dir)
	pool := g.FindOne("Pool")
	fn := pool.Functions["flashLoan"]
	m := tracker.Analyze(fn, pool)

	if !m.HasWriteAfterCall() {
		t.Error("flash loan: totalBorrowed write after callback should be detected")
	}
	violations := m.FindCEIViolations()
	if len(violations) == 0 {
		t.Fatal("flash loan: expected CEI violation for totalBorrowed after callback")
	}
}

// Helpers.

func buildGraphWithTracker(
	t *testing.T,
	dir string,
) (*inheritancegraph.Graph, *inheritancegraph.StateTracker) {
	t.Helper()
	g := buildGraph(t, dir)
	g.EnrichFunctions()
	g.EnrichModifiers()
	return g, inheritancegraph.NewStateTracker(g)
}

func filterOps(ops []inheritancegraph.StateOp, kind inheritancegraph.OpKind) []inheritancegraph.StateOp {
	var out []inheritancegraph.StateOp
	for _, op := range ops {
		if op.Kind == kind {
			out = append(out, op)
		}
	}
	return out
}

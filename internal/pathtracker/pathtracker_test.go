// internal/pathtracker/pathtracker_test.go

package pathtracker_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/pathtracker"
)

// ── Early Guard Tests ─────────────────────────────────────────────────────────

func TestFindEarlyGuards_MsgSenderRequire(t *testing.T) {
	body := lines(`
        require(msg.sender == owner, "not owner");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
    `)
	pt := pathtracker.New()
	guards := pt.FindEarlyGuards(body)

	if len(guards) == 0 {
		t.Fatal("require(msg.sender == owner) should be detected as guard")
	}
	if guards[0].Kind != pathtracker.GuardAccessControl {
		t.Errorf("kind = %v, want GuardAccessControl", guards[0].Kind)
	}
}

func TestFindEarlyGuards_IfRevert(t *testing.T) {
	body := lines(`
        if (msg.sender != admin) revert Unauthorized();
        state = newValue;
    `)
	pt := pathtracker.New()
	guards := pt.FindEarlyGuards(body)

	if len(guards) == 0 {
		t.Fatal("if+revert should be detected as guard")
	}
	if !guards[0].IsAccessControl() {
		t.Error("msg.sender != admin guard should be access-control kind")
	}
}

func TestFindEarlyGuards_ReentrancyGuard(t *testing.T) {
	body := lines(`
        require(!_locked, "Reentrant");
        _locked = true;
        (bool ok,) = addr.call{value: x}("");
        _locked = false;
    `)
	pt := pathtracker.New()
	guards := pt.FindEarlyGuards(body)

	if len(guards) == 0 {
		t.Fatal("require(!_locked) should be detected as reentrancy guard")
	}
	if !guards[0].IsReentrancyGuard() {
		t.Errorf("kind = %v, want GuardReentrancy", guards[0].Kind)
	}
}

func TestFindEarlyGuards_StopsAtStateWrite(t *testing.T) {
	body := lines(`
        // No guard here
        balances[msg.sender] -= amount;    // state write
        require(msg.sender == owner);      // this is NOT an early guard
    `)
	pt := pathtracker.New()
	guards := pt.FindEarlyGuards(body)

	// The require after a state write should not be detected as an early guard
	for _, g := range guards {
		if g.IsAccessControl() {
			t.Error("require after state write should not be an early guard")
		}
	}
}

func TestHasAccessControlGuard(t *testing.T) {
	body := lines(`
        require(msg.sender == owner);
        fee = newFee;
    `)
	pt := pathtracker.New()

	if !pt.HasAccessControlGuard(body) {
		t.Error("HasAccessControlGuard = false, want true")
	}
}

func TestHasAccessControlGuard_False(t *testing.T) {
	body := lines(`
        require(amount > 0);
        balances[msg.sender] -= amount;
    `)
	pt := pathtracker.New()

	if pt.HasAccessControlGuard(body) {
		t.Error("HasAccessControlGuard = true for amount check, want false")
	}
}

// ── Custom Mutex Tests ────────────────────────────────────────────────────────

func TestFindCustomMutex_FullPattern(t *testing.T) {
	contractSrc := `
contract Vault {
    bool private _locked;

    function withdraw(uint256 amount) external {
        require(!_locked, "Reentrant");
        _locked = true;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        _locked = false;
    }
}`
	body := extractBody(contractSrc, "withdraw")
	pt := pathtracker.New()
	mutex := pt.FindCustomMutex(body, contractSrc)

	if mutex == nil {
		t.Fatal("full mutex pattern not detected")
	}
	if mutex.LockVar != "_locked" {
		t.Errorf("lockVar = %q, want _locked", mutex.LockVar)
	}
	if mutex.CheckLine >= mutex.SetLine {
		t.Error("check should come before set")
	}
	if mutex.SetLine >= mutex.ResetLine {
		t.Error("set should come before reset")
	}
}

func TestFindCustomMutex_NotAStatVar_NoFinding(t *testing.T) {
	contractSrc := `
contract T {
    // No bool _locked state var declared
    function withdraw() external {
        bool _locked = false; // local var
        require(!_locked);
        _locked = true;
        addr.call{value: 1}("");
        _locked = false;
    }
}`
	body := extractBody(contractSrc, "withdraw")
	pt := pathtracker.New()
	mutex := pt.FindCustomMutex(body, contractSrc)

	if mutex != nil {
		t.Error("local variable should not be detected as mutex")
	}
}

func TestHasReentrancyGuard_CustomMutex(t *testing.T) {
	contractSrc := `
contract T {
    bool private _locked;
    function flash(address r) external {
        require(!_locked);
        _locked = true;
        IReceiver(r).onFlash();
        _locked = false;
    }
}`
	body := extractBody(contractSrc, "flash")
	pt := pathtracker.New()

	if !pt.HasReentrancyGuard(body, contractSrc) {
		t.Error("custom mutex = reentrancy guard present")
	}
}

// ── Branch Context Tests ──────────────────────────────────────────────────────

func TestGetBranchContext_InsideMsgSenderBlock(t *testing.T) {
	body := lines(`
        if (msg.sender == owner) {
            fee = newFee;         ← line index 2
        }
    `)
	pt := pathtracker.New()
	ctx := pt.GetBranchContext(body, 2) // "fee = newFee"

	if ctx == nil {
		t.Fatal("expected branch context")
	}
	if !ctx.HasMsgSenderCheck() {
		t.Error("write inside if(msg.sender==owner) should have msg.sender check")
	}
}

func TestGetBranchContext_OutsideAnyBlock(t *testing.T) {
	body := lines(`
        fee = newFee;         ← line index 0
    `)
	pt := pathtracker.New()
	ctx := pt.GetBranchContext(body, 0)

	if ctx == nil {
		t.Fatal("expected context even at top level")
	}
	if ctx.HasMsgSenderCheck() {
		t.Error("top-level write should not have msg.sender check")
	}
	if len(ctx.Conditions) != 0 {
		t.Errorf("top-level: conditions = %d, want 0", len(ctx.Conditions))
	}
}

func TestIsConditionalWrite_AccessControlled(t *testing.T) {
	body := lines(`
        if (msg.sender == owner) {
            admin = newAdmin;       ← line index 2
        }
    `)
	pt := pathtracker.New()
	cw := pt.IsConditionalWrite(body, 2, "admin")

	if cw == nil {
		t.Fatal("expected ConditionalWrite")
	}
	if !cw.IsAccessControlled {
		t.Error("write inside if(msg.sender==owner) = access controlled")
	}
}

// ── Integration: reduces false positives in detectors ────────────────────────

func TestPathTracker_ReducesFP_AccessControl(t *testing.T) {
	// This is a pattern that used to generate false positives:
	// admin action without a modifier, but with inline require guard.
	body := lines(`
        require(msg.sender == admin, "not admin");
        treasury = newTreasury;
        emit TreasuryChanged(newTreasury);
    `)
	pt := pathtracker.New()

	if !pt.HasAccessControlGuard(body) {
		t.Error("inline require guard should eliminate FP")
	}
}

func TestPathTracker_ReducesFP_Reentrancy(t *testing.T) {
	contractSrc := `
contract T {
    bool private locked;
    uint256 public balance;

    function withdraw() external {
        require(!locked);
        locked = true;
        uint256 amt = balance;
        balance = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        locked = false;
    }
}`
	body := extractBody(contractSrc, "withdraw")
	pt := pathtracker.New()

	if !pt.HasReentrancyGuard(body, contractSrc) {
		t.Error("custom mutex should be detected — no FP expected on reentrancy")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func lines(s string) []string {
	return strings.Split(strings.TrimSpace(s), "\n")
}

func extractBody(src, funcName string) []string {
	// Find function body between first { after function name and matching }
	funcRe := regexp.MustCompile(`function\s+` + funcName + `\s*\(`)
	lines := strings.Split(src, "\n")
	var body []string
	depth := 0
	inFunc := false

	for _, line := range lines {
		if !inFunc {
			if funcRe.MatchString(line) {
				inFunc = true
			}
			if inFunc && strings.Contains(line, "{") {
				depth++
			}
			continue
		}
		body = append(body, line)
		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth == 0 {
			break
		}
	}
	return body
}

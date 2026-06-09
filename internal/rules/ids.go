package rules

//
// Numbering convention:
//   001-099: Primary / well-known vulnerabilities
//   100-199: Variant / context-specific
//   200-299: Best practice / informational

const (
	// --- Reentrancy ---
	IDReentrancy001 RuleID = "SOLSEC-REENTRANCY-001" // Classic CEI violation
	IDReentrancy002 RuleID = "SOLSEC-REENTRANCY-002" // Cross-function reentrancy
	IDReentrancy003 RuleID = "SOLSEC-REENTRANCY-003" // Read-only reentrancy
	IDReentrancy004 RuleID = "SOLSEC-REENTRANCY-004" // Cross-contract reentrancy

	// --- Authentication ---
	IDTxOrigin001 RuleID = "SOLSEC-AUTH-001" // tx.origin misuse
	IDTxOrigin002 RuleID = "SOLSEC-AUTH-002" // tx.origin == msg.sender (safe pattern, info)

	// --- Access Control ---
	IDAccessControl001 RuleID = "SOLSEC-ACCESS-001" // Missing access control on critical fn
	IDAccessControl002 RuleID = "SOLSEC-ACCESS-002" // Weak access control (address(0) check)
	IDAccessControl003 RuleID = "SOLSEC-ACCESS-003" // Unprotected state variable write
	IDAccessControl004 RuleID = "SOLSEC-ACCESS-004" // Centralization risk (single owner)

	// --- Arithmetic ---
	IDIntegerOverflow001 RuleID = "SOLSEC-ARITHMETIC-001" // Overflow (old Solidity, no SafeMath)
	IDIntegerOverflow002 RuleID = "SOLSEC-ARITHMETIC-002" // Unchecked block arithmetic
	IDIntegerOverflow003 RuleID = "SOLSEC-ARITHMETIC-003" // Unsafe downcast

	// --- Call Safety ---
	IDUncheckedCall001 RuleID = "SOLSEC-CALL-001" // Unchecked .call() return
	IDUncheckedCall002 RuleID = "SOLSEC-CALL-002" // Unchecked .send() return
	IDDelegatecall001  RuleID = "SOLSEC-CALL-003" // Unprotected delegatecall
	IDDelegatecall002  RuleID = "SOLSEC-CALL-004" // User-controlled delegatecall target
	IDDelegatecall003  RuleID = "SOLSEC-CALL-005" // Proxy fallback delegatecall

	// --- Upgrade ---
	IDUpgrade001 RuleID = "SOLSEC-UPGRADE-001" // Unprotected implementation upgrade
	IDUpgrade002 RuleID = "SOLSEC-UPGRADE-002" // Proxy access control bypass
	IDUpgrade003 RuleID = "SOLSEC-UPGRADE-003" // Storage collision risk

	// --- On-Chain ---
	IDOnChain001 RuleID = "SOLSEC-ONCHAIN-001" // Unverified contract
	IDOnChain002 RuleID = "SOLSEC-ONCHAIN-002" // Bytecode mismatch
	IDOnChain003 RuleID = "SOLSEC-ONCHAIN-003" // SELFDESTRUCT opcode
	IDOnChain004 RuleID = "SOLSEC-ONCHAIN-004" // DELEGATECALL in bytecode
	IDOnChain005 RuleID = "SOLSEC-ONCHAIN-005" // tx.origin in bytecode
	IDOnChain006 RuleID = "SOLSEC-ONCHAIN-006" // Known exploited contract

	// --- Inter-Contract ---
	IDInterContract001 RuleID = "SOLSEC-INTERCONTRACT-001" // Cross-contract reentrancy cycle
	IDInterContract002 RuleID = "SOLSEC-INTERCONTRACT-002" // Unprotected cross-contract call
	IDInterContract003 RuleID = "SOLSEC-INTERCONTRACT-003" // Price manipulation risk
	IDInterContract004 RuleID = "SOLSEC-INTERCONTRACT-004" // Cross-contract taint flow

	// --- Shadowing ---
	IDShadowing001 RuleID = "SOLSEC-SHADOW-001" // State variable shadowed by local
	IDShadowing002 RuleID = "SOLSEC-SHADOW-002" // State variable shadowed by parameter

	// --- Initialization ---
	IDInit001 RuleID = "SOLSEC-INIT-001" // Reinitializable initializer
	IDInit002 RuleID = "SOLSEC-INIT-002" // Constructor in upgradeable
	IDInit003 RuleID = "SOLSEC-INIT-003" // Missing storage gap in upgradeable contract
	IDInit004 RuleID = "SOLSEC-INIT-004" // Uninitialized Ownable
	IDInit005 RuleID = "SOLSEC-INIT-005" // Override removes restriction

	// Flash loan callback detector.
	IDDefi001 RuleID = "SOLSEC-DEFI-001" // Flash loan provider missing guard
	IDDefi002 RuleID = "SOLSEC-DEFI-002" // Flash loan callback missing caller check
	IDDefi003 RuleID = "SOLSEC-DEFI-003" // Signature replay

)

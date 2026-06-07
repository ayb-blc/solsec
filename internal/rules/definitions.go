package rules

func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, rule := range defaultRules() {
		r.Register(rule)
	}
	return r
}

func defaultRules() []*Rule {
	return []*Rule{
		rule(IDReentrancy001, "Reentrancy", SeverityCritical, ConfidenceHigh, CategoryReentrancy, "reentrancy",
			"External call before state update may allow reentrancy.",
			"Move state updates before external calls and use a reentrancy guard for sensitive functions.",
			[]string{"SWC-107"}, []string{"CWE-841"}, []string{"reentrancy", "cei"}),
		rule(IDReentrancy002, "Cross-function reentrancy", SeverityHigh, ConfidenceMedium, CategoryReentrancy, "reentrancy",
			"Shared state can be reentered through another function before invariants are restored.",
			"Protect related entry points with the same guard and update shared state before interactions.",
			[]string{"SWC-107"}, []string{"CWE-841"}, []string{"reentrancy", "cross-function"}),
		rule(IDReentrancy003, "Read-only reentrancy", SeverityMedium, ConfidenceMedium, CategoryReentrancy, "reentrancy",
			"External calls may observe inconsistent state through view-like paths.",
			"Avoid exposing price/accounting views during mutable external interactions.",
			[]string{"SWC-107"}, []string{"CWE-841"}, []string{"reentrancy", "read-only"}),
		rule(IDReentrancy004, "Cross-contract reentrancy", SeverityHigh, ConfidenceMedium, CategoryReentrancy, "reentrancy",
			"External contract interactions can reenter through a different contract boundary.",
			"Model cross-contract invariants and apply guards around the full interaction surface.",
			[]string{"SWC-107"}, []string{"CWE-841"}, []string{"reentrancy", "cross-contract"}),

		rule(IDTxOrigin001, "tx.origin authentication", SeverityHigh, ConfidenceHigh, CategoryAuthentication, "tx-origin",
			"Using tx.origin for authorization can be bypassed through phishing contracts.",
			"Use msg.sender for authorization and reserve tx.origin only for non-authentication telemetry.",
			[]string{"SWC-115"}, []string{"CWE-287"}, []string{"authentication", "tx-origin"}),
		rule(IDTxOrigin002, "tx.origin EOA check", SeverityInformational, ConfidenceMedium, CategoryAuthentication, "tx-origin",
			"tx.origin == msg.sender is usually an EOA gate, not owner authentication.",
			"Prefer explicit access control; avoid blocking composability unless EOA-only behavior is intentional.",
			nil, []string{"CWE-346"}, []string{"authentication", "eoa"}),

		rule(IDAccessControl001, "Missing access control", SeverityCritical, ConfidenceHigh, CategoryAccessControl, "access-control",
			"Sensitive functions can be called without an owner, role, or authorization check.",
			"Add explicit access control such as onlyOwner or role-based authorization.",
			[]string{"SWC-105"}, []string{"CWE-284"}, []string{"access-control"}),
		rule(IDAccessControl002, "Weak access control", SeverityHigh, ConfidenceMedium, CategoryAccessControl, "access-control",
			"Authorization checks appear incomplete or easy to bypass.",
			"Use a clear authority model and validate privileged callers explicitly.",
			[]string{"SWC-105"}, []string{"CWE-284"}, []string{"access-control"}),
		rule(IDAccessControl003, "Unprotected state write", SeverityHigh, ConfidenceMedium, CategoryAccessControl, "access-control",
			"Externally callable code can write sensitive state without sufficient authorization.",
			"Restrict sensitive state mutations to trusted roles.",
			[]string{"SWC-105"}, []string{"CWE-284"}, []string{"access-control", "state-write"}),
		rule(IDAccessControl004, "Centralization risk", SeverityMedium, ConfidenceMedium, CategoryAccessControl, "access-control",
			"A single privileged account controls sensitive behavior.",
			"Use multisig, timelocks, or role separation for high-impact administration.",
			nil, []string{"CWE-284"}, []string{"access-control", "centralization"}),

		{
			ID:               IDInit001,
			Name:             "Reinitializable Initializer",
			ShortDescription: "initialize() function lacks protection and can be called multiple times.",
			FullDescription: `An initialize() function with public or external visibility has no protection
against being called more than once. Without the OpenZeppelin initializer
modifier or an explicit initialized flag, anyone can call this function after
deployment and overwrite critical state.

Severity depends on what the initializer sets:
  CRITICAL - sets owner/admin/token/oracle/implementation or grants roles
  HIGH     - writes other state variables
  MEDIUM   - minimal body such as events or constants only

Real-world exploits:
  Wormhole (2022, $320M) - signature verification bypass via re-initialization
  Audius   (2022,   $6M) - governance takeover via front-run initialize()`,
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Category:     CategoryAccessControl,
			Language:     LanguageSolidity,
			DetectorName: "reinitializable-init",
			Tags:         []string{"initialization", "upgradeable", "proxy", "access-control"},
			Remediation: `Add OpenZeppelin's initializer modifier:

  import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

  contract MyContract is Initializable {
      function initialize(address owner_) external initializer {
          // runs exactly once
      }
  }

If you cannot use OpenZeppelin, add a manual guard:

  bool private _initialized;

  function initialize(...) external {
      require(!_initialized, "Already initialized");
      _initialized = true;
      ...
  }`,
			References: RuleReferences{
				SWC: []string{"SWC-105"},
				CWE: []string{"CWE-665", "CWE-284"},
				URLs: []string{
					"https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable",
					"https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a",
				},
			},
			Examples: RuleExamples{
				Vulnerable: `function initialize(address owner_, address token_) public {
    owner = owner_;
    token = IERC20(token_);
}`,
				Safe: `function initialize(address owner_, address token_) external initializer {
    owner = owner_;
    token = IERC20(token_);
}`,
			},
			Enabled: true,
		},
		{
			ID:               IDInit002,
			Name:             "Constructor in Upgradeable Contract",
			ShortDescription: "Upgradeable contract constructor writes state that will not initialize proxy storage.",
			FullDescription: `Constructors run on the implementation contract, not on the proxy storage
used by users. In upgradeable contracts, constructor logic that writes owner,
admin, oracle, token, implementation, roles, or other state variables will not
initialize the proxy.

Safe constructor patterns include an empty constructor or OpenZeppelin's
recommended _disableInitializers() call.

Severity depends on what the constructor does:
  CRITICAL - sets owner/admin/token/oracle/implementation or grants roles
  HIGH     - writes other state variables`,
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Category:     CategoryUpgrade,
			Language:     LanguageSolidity,
			DetectorName: "constructor-in-upgradeable",
			Tags:         []string{"initialization", "upgradeable", "proxy", "constructor"},
			Remediation: `Move initialization logic from the constructor into initialize(), and keep only
the implementation hardening constructor:

  constructor() {
      _disableInitializers();
  }

  function initialize(address owner_) external initializer {
      owner = owner_;
  }`,
			References: RuleReferences{
				CWE: []string{"CWE-665"},
				URLs: []string{
					"https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable",
					"https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable-_disableInitializers--",
				},
			},
			Examples: RuleExamples{
				Vulnerable: `contract Vault is Initializable {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }
}`,
				Safe: `contract Vault is Initializable {
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        owner = owner_;
    }
}`,
			},
			Enabled: true,
		},
		{
			ID:               IDInit003,
			Name:             "Missing Storage Gap in Upgradeable Contract",
			ShortDescription: "Upgradeable contract has state variables but no __gap; consider reserving slots for future upgrades.",
			FullDescription: `Upgradeable contracts that may be inherited by other contracts should reserve
storage space via a __gap array. Without it, adding a new state variable to a
base contract in a future upgrade can shift storage slots in child contracts.

This finding is informational. Whether __gap is required depends on the upgrade
strategy:

  - If this contract will never be inherited, __gap may not be needed
  - If child contracts exist or are planned, consider adding __gap
  - If using a storage-namespaced pattern such as EIP-7201, __gap is not needed
  - If this is a final implementation behind a proxy, verify the upgrade path

The OpenZeppelin convention is 50 slots total per base contract:
  uint256[50 - N] private __gap;  // N = slots already used`,
			Severity:     SeverityLow,
			Confidence:   ConfidenceLow,
			Category:     CategoryUpgrade,
			Language:     LanguageSolidity,
			DetectorName: "storage-gap-missing",
			Tags:         []string{"upgradeable", "storage", "proxy", "gap", "best-practice"},
			Remediation: `Consider adding a __gap array if this contract is or may be inherited:

  contract MyBase is Initializable {
      uint256 public fee;        // slot 0
      address public treasury;   // slot 1
      uint256[48] private __gap; // 50 - 2 = 48 slots reserved

      // Adding new variables in a future upgrade:
      // uint256 public newVar;      // slot 2 (was gap[0])
      // uint256[47] private __gap;  // adjust size
  }

If using EIP-7201 namespaced storage, __gap is not required.`,
			References: RuleReferences{
				CWE: []string{"CWE-665"},
				URLs: []string{
					"https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#storage-gaps",
					"https://eips.ethereum.org/EIPS/eip-7201",
				},
			},
			Examples: RuleExamples{
				Vulnerable: `abstract contract BaseVault is Initializable {
    uint256 public fee;
    address public treasury;
}`,
				Safe: `abstract contract BaseVault is Initializable {
    uint256 public fee;
    address public treasury;
    uint256[48] private __gap;
}`,
			},
			Enabled: true,
		},
		{
			ID:               IDInit004,
			Name:             "Uninitialized OwnableUpgradeable",
			ShortDescription: "OwnableUpgradeable inheritance is present but ownership is not initialized.",
			FullDescription: `Contracts that inherit OwnableUpgradeable must initialize ownership during
their initializer flow. Unlike regular Ownable constructors, upgradeable
contracts do not run constructor-based owner setup through the proxy.

This rule is intentionally strong for OwnableUpgradeable and conservative for
regular Ownable. OpenZeppelin v4 Ownable sets the owner in the constructor, and
OpenZeppelin v5 Ownable(address initialOwner) requires constructor ownership
configuration. OwnableUpgradeable requires __Ownable_init(),
__Ownable_init_unchained(), _transferOwnership(), or equivalent ownership setup
from initialize().`,
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Category:     CategoryAccessControl,
			Language:     LanguageSolidity,
			DetectorName: "uninitialized-ownable",
			Tags:         []string{"initialization", "upgradeable", "proxy", "ownable", "access-control"},
			Remediation: `Call OwnableUpgradeable initialization from the contract initializer:

  function initialize(address owner_) external initializer {
      __Ownable_init();
      _transferOwnership(owner_);
  }

For OpenZeppelin versions where __Ownable_init accepts an owner parameter, pass
the intended owner directly.`,
			References: RuleReferences{
				CWE: []string{"CWE-665", "CWE-284"},
				URLs: []string{
					"https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable",
					"https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable",
				},
			},
			Examples: RuleExamples{
				Vulnerable: `contract Vault is Initializable, OwnableUpgradeable {
    function initialize() external initializer {
        // missing __Ownable_init or ownership transfer
    }
}`,
				Safe: `contract Vault is Initializable, OwnableUpgradeable {
    function initialize(address owner_) external initializer {
        __Ownable_init();
        _transferOwnership(owner_);
    }
}`,
			},
			Enabled: true,
		},
		{
			ID:               IDInit005,
			Name:             "Override Removes Restriction",
			ShortDescription: "An overriding function removes access-control restrictions from a parent function.",
			FullDescription: `Inheritance can silently weaken authorization when a child contract overrides
a restricted parent function without preserving an equivalent access-control
modifier.

The detector compares same-file parent and child contracts by function name and
parameter count. It treats access-control modifiers as a class rather than
requiring the exact same modifier name, so onlyOwner -> onlyAdmin is considered
restricted. Interface implementations are skipped because interfaces do not
carry executable restrictions.

Severity depends on analysis confidence and impact:
  CRITICAL - same-file parent restriction is removed and the child writes state
  HIGH     - same-file parent restriction is removed without obvious state write
  MEDIUM   - parent is unknown, the override has a sensitive name, and no restriction remains`,
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Category:     CategoryAccessControl,
			Language:     LanguageSolidity,
			DetectorName: "override-removes-restriction",
			Tags:         []string{"inheritance", "override", "access-control"},
			Remediation: `Preserve an equivalent access-control modifier on overrides:

  function setFee(uint256 fee) external override onlyOwner {
      ...
  }

If the restriction intentionally changes, document the authorization model and
use a modifier with equivalent protection such as onlyAdmin or onlyRole.`,
			References: RuleReferences{
				CWE: []string{"CWE-284", "CWE-266"},
			},
			Examples: RuleExamples{
				Vulnerable: `contract Base {
    function setFee(uint256 fee) external virtual onlyOwner {}
}

contract Child is Base {
    function setFee(uint256 fee) external override {
        feeBps = fee;
    }
}`,
				Safe: `contract Child is Base {
    function setFee(uint256 fee) external override onlyAdmin {
        feeBps = fee;
    }
}`,
			},
			Enabled: false,
		},

		rule(IDIntegerOverflow001, "Integer overflow or underflow", SeverityHigh, ConfidenceMedium, CategoryArithmetic, "integer-overflow",
			"Arithmetic in old Solidity versions may overflow or underflow.",
			"Use Solidity 0.8+ checked arithmetic or audited SafeMath for older compilers.",
			[]string{"SWC-101"}, []string{"CWE-190"}, []string{"arithmetic"}),
		rule(IDIntegerOverflow002, "Unchecked arithmetic block", SeverityMedium, ConfidenceMedium, CategoryArithmetic, "integer-overflow",
			"unchecked arithmetic disables Solidity overflow checks.",
			"Keep unchecked blocks minimal and prove bounds before arithmetic.",
			[]string{"SWC-101"}, []string{"CWE-190"}, []string{"arithmetic", "unchecked"}),
		rule(IDIntegerOverflow003, "Unsafe downcast", SeverityMedium, ConfidenceMedium, CategoryArithmetic, "integer-overflow",
			"Downcasting can truncate values and break accounting assumptions.",
			"Validate ranges before casting or use safe casting helpers.",
			nil, []string{"CWE-681"}, []string{"arithmetic", "cast"}),

		rule(IDUncheckedCall001, "Unchecked low-level call", SeverityHigh, ConfidenceHigh, CategoryCallSafety, "unchecked-call",
			"Low-level call return value is not checked.",
			"Check the boolean return value and revert on failure.",
			[]string{"SWC-104"}, []string{"CWE-252"}, []string{"call", "unchecked"}),
		rule(IDUncheckedCall002, "Unchecked send", SeverityMedium, ConfidenceHigh, CategoryCallSafety, "unchecked-call",
			"send return value is not checked.",
			"Check the return value or use call with explicit error handling.",
			[]string{"SWC-104"}, []string{"CWE-252"}, []string{"send", "unchecked"}),
		rule(IDDelegatecall001, "Unprotected delegatecall", SeverityCritical, ConfidenceHigh, CategoryCallSafety, "delegatecall",
			"delegatecall can execute code in the caller storage context.",
			"Restrict delegatecall targets and callers; avoid user-controlled implementation addresses.",
			[]string{"SWC-112"}, []string{"CWE-829"}, []string{"delegatecall"}),
		rule(IDDelegatecall002, "User-controlled delegatecall target", SeverityCritical, ConfidenceHigh, CategoryCallSafety, "delegatecall",
			"User-controlled delegatecall target can lead to storage takeover.",
			"Never delegatecall to arbitrary user-provided addresses.",
			[]string{"SWC-112"}, []string{"CWE-829"}, []string{"delegatecall", "user-controlled"}),
		rule(IDDelegatecall003, "Proxy fallback delegatecall", SeverityMedium, ConfidenceMedium, CategoryCallSafety, "delegatecall",
			"Proxy fallback delegates execution to an implementation contract.",
			"Verify upgrade authorization and storage layout compatibility.",
			[]string{"SWC-112"}, []string{"CWE-829"}, []string{"delegatecall", "proxy"}),

		rule(IDUpgrade001, "Unprotected upgrade", SeverityCritical, ConfidenceHigh, CategoryUpgrade, "upgradeability",
			"Implementation upgrade path is not sufficiently protected.",
			"Restrict upgrades to trusted governance and use timelocks/multisig where appropriate.",
			nil, []string{"CWE-284"}, []string{"upgrade", "proxy"}),
		rule(IDUpgrade002, "Proxy access control bypass", SeverityHigh, ConfidenceMedium, CategoryUpgrade, "upgradeability",
			"Proxy or implementation authorization can be bypassed.",
			"Audit proxy admin paths and initializer state.",
			nil, []string{"CWE-284"}, []string{"upgrade", "proxy"}),
		rule(IDUpgrade003, "Storage collision risk", SeverityHigh, ConfidenceMedium, CategoryUpgrade, "upgradeability",
			"Proxy and implementation storage layouts may collide.",
			"Use standardized storage slots and validate layout compatibility before upgrades.",
			nil, []string{"CWE-665"}, []string{"upgrade", "storage"}),

		rule(IDOnChain001, "Unverified contract", SeverityHigh, ConfidenceHigh, CategoryOnChain, "unverified-contract",
			"Deployed source code is not verified on the explorer.",
			"Verify source code and compiler settings on the relevant explorer.",
			nil, []string{"CWE-693"}, []string{"onchain", "verification"}),
		rule(IDOnChain002, "Bytecode mismatch", SeverityCritical, ConfidenceHigh, CategoryOnChain, "bytecode-mismatch",
			"Local or claimed source does not match deployed bytecode.",
			"Rebuild with exact compiler settings and investigate deployment provenance.",
			nil, []string{"CWE-345"}, []string{"onchain", "bytecode"}),
		rule(IDOnChain003, "SELFDESTRUCT in bytecode", SeverityCritical, ConfidenceHigh, CategoryOnChain, "onchain-bytecode-pattern",
			"Runtime bytecode contains SELFDESTRUCT.",
			"Review whether destruction is intentional and access-controlled.",
			[]string{"SWC-106"}, []string{"CWE-284"}, []string{"onchain", "selfdestruct"}),
		rule(IDOnChain004, "DELEGATECALL in bytecode", SeverityHigh, ConfidenceHigh, CategoryOnChain, "onchain-bytecode-pattern",
			"Runtime bytecode contains DELEGATECALL.",
			"Verify proxy/upgrade patterns and target control.",
			[]string{"SWC-112"}, []string{"CWE-829"}, []string{"onchain", "delegatecall"}),
		rule(IDOnChain005, "ORIGIN in bytecode", SeverityHigh, ConfidenceHigh, CategoryOnChain, "onchain-bytecode-pattern",
			"Runtime bytecode reads tx.origin.",
			"Confirm tx.origin is not used for authorization.",
			[]string{"SWC-115"}, []string{"CWE-287"}, []string{"onchain", "tx-origin"}),
		rule(IDOnChain006, "Known exploited contract", SeverityCritical, ConfidenceHigh, CategoryOnChain, "known-exploited-contract",
			"Address appears in known exploit history.",
			"Do not interact with the contract until the incident and code path are understood.",
			nil, []string{"CWE-1104"}, []string{"onchain", "exploit-history"}),

		rule(IDInterContract001, "Cross-contract reentrancy cycle", SeverityCritical, ConfidenceMedium, CategoryInterContract, "intercontract",
			"Call graph contains a cross-contract cycle with external interaction risk.",
			"Break the cycle, isolate accounting updates, or add cross-contract guards.",
			[]string{"SWC-107"}, []string{"CWE-841"}, []string{"intercontract", "reentrancy"}),
		rule(IDInterContract002, "Unprotected cross-contract call", SeverityHigh, ConfidenceMedium, CategoryInterContract, "intercontract",
			"Sensitive cross-contract call path lacks sufficient protection.",
			"Restrict entry points and validate trust boundaries across contracts.",
			nil, []string{"CWE-284"}, []string{"intercontract", "access-control"}),
		rule(IDInterContract003, "Price manipulation risk", SeverityHigh, ConfidenceMedium, CategoryInterContract, "intercontract",
			"External price dependency may be manipulated across contract interactions.",
			"Use robust oracle design, TWAPs, and liquidity-aware checks.",
			nil, []string{"CWE-345"}, []string{"intercontract", "oracle"}),
		rule(IDInterContract004, "Cross-contract taint flow", SeverityMedium, ConfidenceMedium, CategoryInterContract, "intercontract",
			"Untrusted data flows across contract boundaries into sensitive sinks.",
			"Validate and sanitize cross-contract inputs before use.",
			nil, []string{"CWE-20"}, []string{"intercontract", "taint"}),

		rule(IDShadowing001, "State variable shadowed by local", SeverityLow, ConfidenceHigh, CategoryShadowing, "shadowing",
			"Local variable shadows a state variable and can confuse review.",
			"Rename the local variable or use explicit state access.",
			nil, []string{"CWE-710"}, []string{"shadowing"}),
		rule(IDShadowing002, "State variable shadowed by parameter", SeverityLow, ConfidenceHigh, CategoryShadowing, "shadowing",
			"Function parameter shadows a state variable.",
			"Rename the parameter to make state access unambiguous.",
			nil, []string{"CWE-710"}, []string{"shadowing"}),
	}
}

func rule(id RuleID, name string, severity Severity, confidence Confidence, category Category, detector, desc, remediation string, swc, cwe, tags []string) *Rule {
	return &Rule{
		ID:               id,
		Name:             name,
		ShortDescription: desc,
		FullDescription:  desc,
		Severity:         severity,
		Confidence:       confidence,
		Category:         category,
		Language:         LanguageBoth,
		Tags:             tags,
		Remediation:      remediation,
		References: RuleReferences{
			SWC: swc,
			CWE: cwe,
		},
		Examples: RuleExamples{
			Vulnerable: vulnerableExample(id),
			Safe:       safeExample(id),
		},
		Enabled:      true,
		DetectorName: detector,
	}
}

func vulnerableExample(id RuleID) string {
	if id == IDReentrancy001 {
		return `function withdraw() external {
    (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
    require(ok);
    balances[msg.sender] = 0;
}`
	}
	if id == IDAccessControl001 {
		return `function mint(address to, uint256 amount) external {
    _mint(to, amount);
}`
	}
	if id == IDDelegatecall001 || id == IDDelegatecall002 || id == IDOnChain002 || id == IDOnChain003 || id == IDInterContract001 || id == IDOnChain006 || id == IDUpgrade001 {
		return `function execute(address target, bytes calldata data) external {
    target.delegatecall(data);
}`
	}
	return ""
}

func safeExample(id RuleID) string {
	if id == IDReentrancy001 {
		return `function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}`
	}
	if id == IDAccessControl001 {
		return `function mint(address to, uint256 amount) external onlyOwner {
    _mint(to, amount);
}`
	}
	if id == IDDelegatecall001 || id == IDDelegatecall002 || id == IDOnChain002 || id == IDOnChain003 || id == IDInterContract001 || id == IDOnChain006 || id == IDUpgrade001 {
		return `function upgradeTo(address implementation) external onlyOwner {
    _upgradeTo(implementation);
}`
	}
	return ""
}

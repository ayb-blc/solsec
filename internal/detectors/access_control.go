package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/pathtracker"
)

// AccessControlDetector finds missing or weak authorization around sensitive actions.
type AccessControlDetector struct {
	criticalFunctionNames []*regexp.Regexp

	accessControlPatterns []*regexp.Regexp

	weakControlPatterns []*regexp.Regexp

	criticalStateVarPatterns []*regexp.Regexp
}

var (
	internalFuncRe   = regexp.MustCompile(`\b(?:internal|private)\b`)
	underscoreFuncRe = regexp.MustCompile(`^\s*function\s+_\w+`)
	overrideFuncRe   = regexp.MustCompile(`\boverride\b`)
	virtualFuncRe    = regexp.MustCompile(`\bvirtual\b`)
	constructorRe    = regexp.MustCompile(`^\s*constructor\s*\(`)
	viewPureFuncRe   = regexp.MustCompile(`\b(?:view|pure)\b`)

	safeAccessModifiers = map[string]bool{
		"onlyOwner":                    true,
		"onlyAdmin":                    true,
		"onlyRole":                     true,
		"onlyMinter":                   true,
		"onlyBurner":                   true,
		"onlyOperator":                 true,
		"onlyGovernor":                 true,
		"onlyGuardian":                 true,
		"requiresAuth":                 true,
		"auth":                         true,
		"protected":                    true,
		"restricted":                   true,
		"nonReentrant":                 true,
		"whenNotPaused":                true,
		"initializer":                  true,
		"reinitializer":                true,
		"onlyInitializing":             true,
		"ifAdmin":                      true,
		"onlyProxyAdmin":               true,
		"adminOnly":                    true,
		"ifAdminOrPending":             true,
		"lock":                         true,
		"ensure":                       true,
		"noDelegateCall":               true,
		"checkDeadline":                true,
		"validRecipient":               true,
		"onlyPoolAdmin":                true,
		"onlyEmergencyAdmin":           true,
		"onlyEmergencyOrPoolAdmin":     true,
		"onlyAssetListingOrPoolAdmins": true,
		"onlyRiskOrPoolAdmins":         true,
		"onlyPoolConfigurator":         true,
		"onlyBridge":                   true,
		"onlyPool":                     true,
	}
)

func NewAccessControlDetector() *AccessControlDetector {
	return &AccessControlDetector{
		criticalFunctionNames: []*regexp.Regexp{
			// Token operations
			regexp.MustCompile(`\bfunction\s+mint\s*\(`),
			regexp.MustCompile(`\bfunction\s+burn\s*\(`),
			// Admin operations
			regexp.MustCompile(`\bfunction\s+(set|update|change)(Owner|Admin|Minter|Pauser)\s*\(`),
			regexp.MustCompile(`\bfunction\s+transferOwnership\s*\(`),
			regexp.MustCompile(`\bfunction\s+(add|remove)(Admin|Minter|Role)\s*\(`),
			// Upgrade operations
			regexp.MustCompile(`\bfunction\s+upgrade(To|Implementation)\s*\(`),
			regexp.MustCompile(`\bfunction\s+setImplementation\s*\(`),
			// Financial/admin operations. Plain withdraw() is intentionally
			// excluded: user balance withdrawals are often public by design and
			// belong to reentrancy/unchecked-call analysis, not access control.
			regexp.MustCompile(`\bfunction\s+(withdrawAll|sweep|rescue|recover)(ETH|Ether|Token|Funds|Assets)?\s*\(`),
			regexp.MustCompile(`\bfunction\s+emergencyWithdraw\s*\(`),
			// Pause operations
			regexp.MustCompile(`\bfunction\s+(pause|unpause)\s*\(`),
			// Parameter changes
			regexp.MustCompile(`\bfunction\s+set(Fee|Rate|Price|Limit|Cap)\s*\(`),
		},

		accessControlPatterns: []*regexp.Regexp{
			// Modifier based
			regexp.MustCompile(`\bonlyOwner\b`),
			regexp.MustCompile(`\bonlyAdmin\b`),
			regexp.MustCompile(`\bonlyRole\b`),
			regexp.MustCompile(`\bonlyMinter\b`),
			regexp.MustCompile(`\bonlyPauser\b`),
			regexp.MustCompile(`\bwhenNotPaused\b`),
			// Require based
			regexp.MustCompile(`require\s*\(\s*msg\.sender\s*==\s*(owner|admin|_owner|_admin)`),
			regexp.MustCompile(`require\s*\(\s*(owner|admin|_owner)\s*==\s*msg\.sender`),
			regexp.MustCompile(`require\s*\(\s*hasRole\s*\(`),
			regexp.MustCompile(`require\s*\(\s*isOwner\s*\(`),
			regexp.MustCompile(`_checkOwner\s*\(`),
			regexp.MustCompile(`_checkRole\s*\(`),
			// AccessControl pattern
			regexp.MustCompile(`AccessControl`),
			regexp.MustCompile(`Ownable`),
		},

		weakControlPatterns: []*regexp.Regexp{
			regexp.MustCompile(`require\s*\(\s*msg\.sender\s*!=\s*address\s*\(\s*0\s*\)`),
			regexp.MustCompile(`require\s*\(\s*true\s*\)`),
		},

		criticalStateVarPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*_?owner\s*=`),
			regexp.MustCompile(`(?m)^\s*_?admin\s*=`),
			regexp.MustCompile(`(?m)^\s*_?implementation\s*=`),
			regexp.MustCompile(`(?m)^\s*_?minter\s*=`),
			regexp.MustCompile(`(?m)^\s*_?pauser\s*=`),
		},
	}
}

func (d *AccessControlDetector) Name() string                { return "access-control" }
func (d *AccessControlDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *AccessControlDetector) Description() string {
	return "Detects missing or weak access controls on sensitive functions"
}

func (d *AccessControlDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	functions := extractFunctionBlocks(lines)
	pt := pathtracker.New()

	for _, fn := range functions {
		if fn.visibility == "internal" || fn.visibility == "private" {
			continue
		}
		if pt.HasAccessControlGuard(functionBodyForPathTracking(fn.lines)) {
			continue
		}

		fnSource := strings.Join(fn.lines, "\n")
		findings = append(findings, d.analyzeFunction(fn, fnSource, filepath)...)
	}

	return findings, nil
}

func (d *AccessControlDetector) analyzeFunction(
	fn functionBlock,
	fnSource string,
	filepath string,
) []analyzer.Finding {
	var findings []analyzer.Finding
	if isNonProductionAccessControlPath(filepath) {
		return nil
	}
	if isInterfaceOrAbstractSignature(fn.signature, fn.lines) {
		return nil
	}
	if isFunctionSafeFromAC(fn.signature, fn.lines) {
		return nil
	}
	if fn.name == "initialize" && hasManualInitializerGuard(fn.lines) {
		return nil
	}
	if fn.name == "burn" && burnsCallerOwnedAsset(fn.lines) {
		return nil
	}
	if fn.name == "mint" && isUserInitiatedVaultMint(fn.lines) {
		return nil
	}
	if fn.name == "mint" && !isSensitiveMint(fn.signature, fn.lines) {
		return nil
	}
	if isFunctionInlineProtected(fn.lines) {
		return nil
	}

	hasControl := false
	for _, pattern := range d.accessControlPatterns {
		if pattern.MatchString(fn.signature) || pattern.MatchString(fnSource) {
			hasControl = true
			break
		}
	}

	if !hasControl {
		for _, namePattern := range d.criticalFunctionNames {
			if !namePattern.MatchString("function " + fn.name + "(") {
				continue
			}

			severity := analyzer.High
			confidence := analyzer.ConfidenceHigh

			// Privileged asset movement and ownership changes are CRITICAL.
			if isPrivilegedAssetMovement(fn.name) ||
				fn.name == "mint" ||
				strings.Contains(fn.name, "Owner") ||
				strings.Contains(fn.name, "Admin") {
				severity = analyzer.Critical
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Missing access control on '%s.%s'",
					fn.contractName, fn.name,
				),
				Description: fmt.Sprintf(
					"Function '%s' performs a sensitive operation but has no access control. "+
						"Any external caller can invoke this function.",
					fn.name,
				),
				Recommendation: d.buildAccessControlRecommendation(fn.name),
				Filepath:       filepath,
				Line:           fn.startLine,
				CodeSnippet:    fn.signature,
				Severity:       severity,
				Confidence:     confidence,
				Tags:           []string{"access-control", "missing-modifier", fn.name},
			})
			break
		}
	}

	for _, weakPattern := range d.weakControlPatterns {
		if !weakPattern.MatchString(fnSource) {
			continue
		}

		weakLine := d.findPatternLine(fn, weakPattern)

		findings = append(findings, analyzer.Finding{
			DetectorName: d.Name(),
			Title: fmt.Sprintf(
				"Weak access control in '%s.%s'",
				fn.contractName, fn.name,
			),
			Description: "The access control check in this function is ineffective. " +
				"'require(msg.sender != address(0))' does not restrict access: " +
				"any non-zero address (virtually any wallet) passes this check.",
			Recommendation: "Replace with meaningful access control:\n" +
				"  require(msg.sender == owner, \"Not authorized\");\n" +
				"  // Or use OpenZeppelin's Ownable/AccessControl",
			Filepath:   filepath,
			Line:       weakLine,
			Severity:   analyzer.High,
			Confidence: analyzer.ConfidenceHigh,
			Tags:       []string{"access-control", "weak-check"},
		})
	}

	if !hasControl {
		for _, varPattern := range d.criticalStateVarPatterns {
			if !varPattern.MatchString(fnSource) {
				continue
			}

			if fn.name == "constructor" {
				continue
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Unprotected critical state variable write in '%s.%s'",
					fn.contractName, fn.name,
				),
				Description: fmt.Sprintf(
					"Function '%s' modifies a critical state variable (owner/admin/implementation) "+
						"without access control. An attacker can permanently take over the contract.",
					fn.name,
				),
				Recommendation: "Add access control before any critical state change:\n" +
					"  function setOwner(address newOwner) external onlyOwner {\n" +
					"      require(newOwner != address(0), \"Zero address\");\n" +
					"      emit OwnershipTransferred(owner, newOwner);\n" +
					"      owner = newOwner;\n" +
					"  }",
				Filepath:   filepath,
				Line:       fn.startLine,
				Severity:   analyzer.Critical,
				Confidence: analyzer.ConfidenceHigh,
				Tags:       []string{"access-control", "state-variable", "ownership"},
			})
			break
		}
	}

	return findings
}

func isFunctionSafeFromAC(signature string, body []string) bool {
	if internalFuncRe.MatchString(signature) ||
		underscoreFuncRe.MatchString(signature) ||
		constructorRe.MatchString(signature) ||
		viewPureFuncRe.MatchString(signature) {
		return true
	}
	if overrideFuncRe.MatchString(signature) && !hasSensitiveOperation(body) {
		return true
	}
	if virtualFuncRe.MatchString(signature) && len(body) <= 2 {
		return true
	}
	for _, mod := range extractModifiersFromSig(signature) {
		if safeAccessModifiers[mod] {
			return true
		}
	}
	return false
}

func isNonProductionAccessControlPath(filepath string) bool {
	normalized := strings.ReplaceAll(filepath, "\\", "/")
	return strings.Contains(normalized, "/mocks/") ||
		strings.Contains(normalized, "/test/") ||
		strings.Contains(normalized, "/tests/")
}

func isInterfaceOrAbstractSignature(signature string, body []string) bool {
	trimmed := strings.TrimSpace(signature)
	if strings.HasSuffix(trimmed, ";") {
		return true
	}
	return len(body) <= 1 && !strings.Contains(trimmed, "{")
}

func burnsCallerOwnedAsset(lines []string) bool {
	source := strings.Join(lines, "\n")
	return strings.Contains(source, "_msgSender()") ||
		strings.Contains(source, "msg.sender")
}

func isUserInitiatedVaultMint(lines []string) bool {
	source := strings.Join(lines, "\n")
	return strings.Contains(source, "maxMint(") &&
		strings.Contains(source, "previewMint(") &&
		(strings.Contains(source, "_deposit(_msgSender()") ||
			strings.Contains(source, "_deposit(msg.sender"))
}

func isSensitiveMint(signature string, lines []string) bool {
	if !regexp.MustCompile(`(?i)\bmint\b`).MatchString(signature) {
		return false
	}

	if internalFuncRe.MatchString(signature) {
		return false
	}

	hasExplicitRecipient := regexp.MustCompile(
		`\(\s*address\s+(?:to|receiver|recipient|dst|_to|_receiver)\b`,
	).MatchString(signature)
	if !hasExplicitRecipient {
		return false
	}

	internalMintRe := regexp.MustCompile(`\b_mint\s*\(|\bERC20\._mint\s*\(`)
	for _, line := range lines {
		if internalMintRe.MatchString(line) {
			return true
		}
	}

	return hasExplicitRecipient
}

func isFunctionInlineProtected(lines []string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(\s*msg\.sender\s*==\s*\w+`),
		regexp.MustCompile(`require\s*\(.*msg\.sender.*&&.*msg\.sender\s*==`),
		regexp.MustCompile(`if\s*\(\s*msg\.sender\s*!=\s*\w+(?:\s*&&[^)]+)?\s*\)\s*\{?\s*(?:return|revert)`),
		regexp.MustCompile(`if\s*\(\s*msg\.sender\s*!=\s*\w+\s*\)\s*\{?\s*return\s+fail\s*\(`),
	}

	checkLines := lines
	if len(checkLines) > 15 {
		checkLines = lines[:15]
	}

	for _, line := range checkLines {
		for _, pattern := range patterns {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func hasManualInitializerGuard(lines []string) bool {
	source := strings.Join(lines, "\n")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(\s*!\s*_?initialized\b`),
		regexp.MustCompile(`require\s*\(\s*_?initialized\s*==\s*false\b`),
		regexp.MustCompile(`if\s*\(\s*_?initialized\s*\)\s*(?:revert|return|\{)`),
	}
	for _, pattern := range patterns {
		if pattern.MatchString(source) {
			return true
		}
	}
	return false
}

func hasSensitiveOperation(lines []string) bool {
	sensitiveOps := []string{
		"selfdestruct", "delegatecall",
		"_mint(", ".mint(", "mint(",
		"_burn(", ".burn(", "burn(",
		"_setowner(", "transferownership(",
		"upgradeto(", "upgradetoandcall(",
		"_authorizeupgrade(",
		"pause(", "unpause(",
		"setimplementation(",
		"changeadmin(",
	}
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, op := range sensitiveOps {
			if strings.Contains(lower, op) {
				return true
			}
		}
	}
	return false
}

func extractModifiersFromSig(sig string) []string {
	clean := regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(sig, "()")
	keywords := map[string]bool{
		"function": true, "returns": true, "public": true, "external": true,
		"internal": true, "private": true, "pure": true, "view": true,
		"payable": true, "virtual": true, "override": true, "memory": true,
		"storage": true, "calldata": true,
	}
	words := regexp.MustCompile(`\b[a-zA-Z_]\w*\b`).FindAllString(clean, -1)
	var mods []string
	for _, w := range words {
		if !keywords[w] && !isTypeKeyword(w) {
			mods = append(mods, w)
		}
	}
	return mods
}

func isTypeKeyword(w string) bool {
	return strings.HasPrefix(w, "uint") ||
		strings.HasPrefix(w, "int") ||
		strings.HasPrefix(w, "bytes") ||
		w == "string" ||
		w == "bool" ||
		w == "address"
}

func (d *AccessControlDetector) buildAccessControlRecommendation(fnName string) string {
	base := "Add appropriate access control:\n\n"

	switch {
	case fnName == "mint":
		return base + "  // Option 1: Ownable\n" +
			"  function mint(address to, uint256 amount) external onlyOwner { ... }\n\n" +
			"  // Option 2: Role-based\n" +
			"  bytes32 public constant MINTER_ROLE = keccak256('MINTER_ROLE');\n" +
			"  function mint(...) external onlyRole(MINTER_ROLE) { ... }"

	case isPrivilegedAssetMovement(fnName):
		return base + "  function sweepETH() external onlyOwner {\n" +
			"      uint256 balance = address(this).balance;\n" +
			"      (bool ok,) = owner.call{value: balance}(\"\");\n" +
			"      require(ok);\n" +
			"  }"

	case strings.Contains(fnName, "Owner") || strings.Contains(fnName, "Admin"):
		return base + "  // Use OpenZeppelin's Ownable2Step for safer ownership transfer\n" +
			"  import '@openzeppelin/contracts/access/Ownable2Step.sol';\n" +
			"  contract MyContract is Ownable2Step { ... }"

	default:
		return base + "  modifier onlyOwner() {\n" +
			"      require(msg.sender == owner, \"Not authorized\");\n" +
			"      _;\n" +
			"  }\n" +
			"  function " + fnName + "(...) external onlyOwner { ... }"
	}
}

func (d *AccessControlDetector) findPatternLine(fn functionBlock, pattern *regexp.Regexp) int {
	for i, line := range fn.lines {
		if pattern.MatchString(line) {
			return fn.startLine + i
		}
	}
	return fn.startLine
}

func isPrivilegedAssetMovement(fnName string) bool {
	return strings.Contains(fnName, "withdrawAll") ||
		strings.Contains(fnName, "emergencyWithdraw") ||
		strings.Contains(fnName, "sweep") ||
		strings.Contains(fnName, "rescue") ||
		strings.Contains(fnName, "recover")
}

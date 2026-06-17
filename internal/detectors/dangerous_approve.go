// internal/detectors/dangerous_approve.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// DangerousApproveDetector finds unsafe ERC20 approve() usage patterns.
//
// Checks (in severity order):
//
//  1. User-controlled spender — CRITICAL
//     approve(functionParam, amount): the spender is a caller-controlled value.
//
//  2. Unlimited approval without guard — HIGH
//     approve(X, type(uint256).max) in a function with no access control.
//
//  3. safeApprove (deprecated) — MEDIUM
//     OZ's safeApprove() has the same race condition and is deprecated.
//
//  4. Approve race condition — LOW
//     Direct approve(X, nonZeroAmount) without a preceding approve(X, 0)
//     creates a window where a watcher can double-spend.
type DangerousApproveDetector struct {
	// approve() call
	approveRe *regexp.Regexp

	// safeApprove (deprecated OZ function)
	safeApproveRe *regexp.Regexp

	// forceApprove (safe OZ v5 replacement) — skip if present
	forceApproveRe *regexp.Regexp

	// increaseAllowance / decreaseAllowance — safe alternatives
	safeAllowanceRe *regexp.Regexp

	// Unlimited amount patterns
	maxAmountPatterns []*regexp.Regexp

	// Access control modifiers
	accessControlRe *regexp.Regexp

	// Safe spender targets (constants, immutables, known contracts)
	// These are skipped for the unlimited-approval check.
	safeSpenderPatterns []*regexp.Regexp

	// approve(spender, 0) — revoke or zero-first pattern
	approveZeroRe *regexp.Regexp
}

func NewDangerousApproveDetector() *DangerousApproveDetector {
	return &DangerousApproveDetector{

		// .approve( — matches both token.approve() and IERC20(x).approve()
		approveRe: regexp.MustCompile(
			`\.\s*approve\s*\(`,
		),

		// safeApprove — deprecated, same race condition
		safeApproveRe: regexp.MustCompile(
			`\.\s*safeApprove\s*\(|SafeERC20\s*\.\s*safeApprove\s*\(`,
		),

		// forceApprove — safe OZ v5 replacement
		forceApproveRe: regexp.MustCompile(
			`\.\s*forceApprove\s*\(|SafeERC20\s*\.\s*forceApprove\s*\(`,
		),

		// increaseAllowance / decreaseAllowance — safe alternatives
		safeAllowanceRe: regexp.MustCompile(
			`\.\s*(?:increase|decrease)Allowance\s*\(`,
		),

		// Unlimited amount literals
		maxAmountPatterns: []*regexp.Regexp{
			// type(uint256).max
			regexp.MustCompile(`type\s*\(\s*uint256\s*\)\s*\.\s*max`),
			// 2**256 - 1
			regexp.MustCompile(`2\s*\*\*\s*256\s*-\s*1`),
			// Hex max
			regexp.MustCompile(`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`),
			// Named constants
			regexp.MustCompile(`\b(?:MAX_UINT(?:256)?|UINT256_MAX|MAX_INT256|MAX_ALLOWANCE|UNLIMITED)\b`),
		},

		// Access control modifiers — functions with these are considered protected
		accessControlRe: regexp.MustCompile(
			`\b(?:only[A-Z]\w*|when[A-Z]\w*|` +
				`onlyOwner|onlyAdmin|onlyRole|onlyOperator|` +
				`ifAdmin|restricted|requiresAuth|auth)\b`,
		),

		// approve(spender, 0) — revoking or zero-first pattern
		approveZeroRe: regexp.MustCompile(
			`\.\s*approve\s*\(\s*\w+\s*,\s*0\s*\)`,
		),

		// Safe spender targets: constants, immutables, address(this)
		safeSpenderPatterns: []*regexp.Regexp{
			// address literals
			regexp.MustCompile(`approve\s*\(\s*address\s*\(\s*(?:this|0)\s*\)`),
			// ALL_CAPS constants
			regexp.MustCompile(`approve\s*\(\s*[A-Z][A-Z_0-9]+\s*[,)]`),
			// immutable or constant variable (heuristic: starts uppercase)
			regexp.MustCompile(`approve\s*\(\s*[A-Z][a-zA-Z]+\s*[,)]`),
		},
	}
}

func (d *DangerousApproveDetector) Name() string                { return "dangerous-approve" }
func (d *DangerousApproveDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *DangerousApproveDetector) Description() string {
	return "Detects unsafe ERC20 approve() patterns: user-controlled target, unlimited allowance, race condition"
}

func (d *DangerousApproveDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	fns := extractFunctions(lines)
	var findings []analyzer.Finding

	for _, fn := range fns {
		// Internal/private functions: still check, but lower confidence
		funcText := strings.Join(fn.lines, "\n")

		// Check 1: user-controlled spender (CRITICAL)
		if finding := d.checkUserControlledSpender(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
			continue
		}

		// Check 2: unlimited approval without guard (HIGH)
		if finding := d.checkUnlimitedApproval(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
			continue
		}

		// Check 3: safeApprove deprecated (MEDIUM)
		if finding := d.checkSafeApproveDeprecated(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
		}

		// Check 4: approve race condition (LOW)
		if finding := d.checkApproveRaceCondition(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// ── Check 1: User-controlled spender ─────────────────────────────────────────

// checkUserControlledSpender detects when a function parameter flows
// directly into approve() as the spender address.
func (d *DangerousApproveDetector) checkUserControlledSpender(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.approveRe.MatchString(funcText) {
		return nil
	}

	// Extract address-type parameters from function signature
	addrParams := extractAddressParams(fn.signature)
	if len(addrParams) == 0 {
		return nil
	}

	// Check if any address parameter is used as the approve() spender
	for _, param := range addrParams {
		// Pattern: .approve(param, ...) or .approve( param, ...)
		paramAsSpenderRe := regexp.MustCompile(
			`\.\s*approve\s*\(\s*` + regexp.QuoteMeta(param) + `\s*,`,
		)
		if !paramAsSpenderRe.MatchString(funcText) {
			continue
		}

		snippet := extractMatchingLine(fn.lines, paramAsSpenderRe)
		finding := detectorFinding(rules.IDDefi006, filepath, fn.startLine, snippet)
		finding.Title = "User-controlled approve() target in '" + fn.name + "'"
		finding.Description = "'" + fn.name + "' accepts an address parameter '" + param +
			"' and passes it directly to approve() as the spender.\n\n" +
			"Any caller can supply their own address and grant themselves " +
			"token allowance over the protocol's holdings.\n\n" +
			"Fix: whitelist approved spenders, or remove the address parameter:\n" +
			"  require(trustedSpenders[" + param + "], \"untrusted\");\n" +
			"  token.approve(" + param + ", amount);"
		finding.Confidence = analyzer.ConfidenceHigh

		finding.Severity = analyzer.Critical
		return &finding
	}

	return nil
}

// ── Check 2: Unlimited approval without guard ─────────────────────────────────

// checkUnlimitedApproval flags approve(X, MAX_UINT) in functions that
// lack access control.
func (d *DangerousApproveDetector) checkUnlimitedApproval(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.approveRe.MatchString(funcText) {
		return nil
	}

	// Is there an unlimited amount?
	maxSnippet := ""
	for _, p := range d.maxAmountPatterns {
		if p.MatchString(funcText) {
			maxSnippet = extractMatchingLine(fn.lines, p)
			break
		}
	}
	if maxSnippet == "" {
		return nil
	}

	// Is the function protected by access control?
	if d.accessControlRe.MatchString(fn.signature) {
		return nil
	}

	// Is the spender a safe constant/immutable? (not user-controlled)
	for _, safe := range d.safeSpenderPatterns {
		if safe.MatchString(funcText) {
			return nil
		}
	}

	// constructor() — deployment-time setup is OK
	if fn.name == "constructor" {
		return nil
	}

	finding := detectorFinding(rules.IDDefi006, filepath, fn.startLine, maxSnippet)
	finding.Title = "Unlimited approve() without access control in '" + fn.name + "'"
	finding.Description = "'" + fn.name + "' approves type(uint256).max tokens without access " +
		"control. Any caller can trigger this, and if the approved spender is an " +
		"upgradeable contract, a future upgrade can drain all tokens.\n\n" +
		"Fix: restrict to authorised callers:\n" +
		"  function approveMax(address token, address spender)\n" +
		"      external onlyOwner {\n" +
		"      IERC20(token).approve(spender, type(uint256).max);\n" +
		"  }"
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.High
	return &finding
}

// ── Check 3: safeApprove deprecated ──────────────────────────────────────────

// checkSafeApproveDeprecated flags use of OZ's deprecated safeApprove().
func (d *DangerousApproveDetector) checkSafeApproveDeprecated(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.safeApproveRe.MatchString(funcText) {
		return nil
	}

	// If forceApprove is also present, developer is migrating — skip
	if d.forceApproveRe.MatchString(funcText) {
		return nil
	}

	snippet := extractMatchingLine(fn.lines, d.safeApproveRe)
	finding := detectorFinding(rules.IDDefi006, filepath, fn.startLine, snippet)
	finding.Title = "Deprecated safeApprove() in '" + fn.name + "'"
	finding.Description = "'" + fn.name + "' uses SafeERC20.safeApprove() which is deprecated " +
		"since OpenZeppelin v4.9. It has two problems:\n\n" +
		"  1. Same race condition as approve() — watcher can front-run\n" +
		"  2. Reverts when changing non-zero allowance to non-zero\n\n" +
		"Migration:\n" +
		"  // OZ v5\n" +
		"  SafeERC20.forceApprove(IERC20(token), spender, amount);\n" +
		"  // Or use increaseAllowance / decreaseAllowance for delta changes"
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.Medium
	return &finding
}

// ── Check 4: Approve race condition ──────────────────────────────────────────

// checkApproveRaceCondition flags direct approve() calls that don't
// use the zero-first pattern or increaseAllowance alternative.
func (d *DangerousApproveDetector) checkApproveRaceCondition(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.approveRe.MatchString(funcText) {
		return nil
	}

	// Access-controlled setup functions are usually administrative allowance
	// management. Flagging the generic approve race here creates noise because
	// the caller is trusted and the higher-risk unlimited approval case is
	// handled separately.
	if d.accessControlRe.MatchString(fn.signature) {
		return nil
	}

	// If forceApprove is used → safe (no race condition)
	if d.forceApproveRe.MatchString(funcText) {
		return nil
	}

	// increaseAllowance / decreaseAllowance → safe (delta, not absolute)
	if d.safeAllowanceRe.MatchString(funcText) {
		return nil
	}

	// Already has approve(X, 0) → zero-first pattern → safe
	if d.approveZeroRe.MatchString(funcText) {
		return nil
	}

	// Is the amount actually 0? (revoking — safe)
	approveWithZeroRe := regexp.MustCompile(`\.\s*approve\s*\(\s*\w+\s*,\s*0\s*\)`)
	if approveWithZeroRe.MatchString(funcText) {
		return nil
	}

	// constructor() — first-time setup, no race condition possible
	if fn.name == "constructor" || fn.name == "initialize" {
		return nil
	}

	snippet := extractMatchingLine(fn.lines, d.approveRe)
	finding := detectorFinding(rules.IDDefi006, filepath, fn.startLine, snippet)
	finding.Title = "ERC20 approve() race condition in '" + fn.name + "'"
	finding.Description = "'" + fn.name + "' calls approve() directly without first resetting " +
		"the allowance to zero. If the current allowance is non-zero, a " +
		"watching attacker can front-run the transaction and spend both " +
		"the old and the new allowance.\n\n" +
		"Recommended alternatives:\n" +
		"  // Option 1: increaseAllowance (delta, not absolute)\n" +
		"  token.increaseAllowance(spender, addedAmount);\n\n" +
		"  // Option 2: forceApprove (OZ v5, atomic)\n" +
		"  SafeERC20.forceApprove(IERC20(token), spender, newAmount);\n\n" +
		"  // Option 3: zero-first (two transactions)\n" +
		"  token.approve(spender, 0);\n" +
		"  token.approve(spender, newAmount);"
	finding.Confidence = analyzer.ConfidenceLow // low confidence: allowance might start at 0

	finding.Severity = analyzer.Low
	return &finding
}

// ── helpers ───────────────────────────────────────────────────────────────────

// extractAddressParams returns the names of address-typed parameters
// from a function signature string.
//
// "function approve(address spender, uint256 amount) external"
// → ["spender"]
func extractAddressParams(signature string) []string {
	// Match "address name" patterns in the parameter list
	paramRe := regexp.MustCompile(
		`\baddress(?:\s+payable)?\s+(_?[a-z]\w*)`,
	)
	matches := paramRe.FindAllStringSubmatch(signature, -1)
	var names []string
	for _, m := range matches {
		if len(m) > 1 {
			names = append(names, m[1])
		}
	}
	return names
}

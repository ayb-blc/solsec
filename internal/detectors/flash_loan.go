// internal/detectors/flash_loan.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// FlashLoanDetector detects two distinct flash loan vulnerability patterns:
//
//  1. SOLSEC-DEFI-001: Flash loan provider writes state around a
//     user-controlled callback without a reentrancy guard.
//
//  2. SOLSEC-DEFI-002: Flash loan callback receiver does not verify
//     that msg.sender is a trusted lender.
type FlashLoanDetector struct {
	providerFuncNames *regexp.Regexp

	callbackPatterns []*regexp.Regexp

	receiverFuncNames *regexp.Regexp

	callerVerification []*regexp.Regexp

	reentrancyGuards *regexp.Regexp

	stateWritePatterns []*regexp.Regexp
}

func NewFlashLoanDetector() *FlashLoanDetector {
	return &FlashLoanDetector{

		// Function names that indicate a flash loan provider
		providerFuncNames: regexp.MustCompile(
			`^\s*function\s+(flashLoan|flash|flashBorrow|borrow|flashMint)\s*\(`,
		),

		// Patterns that identify the callback invocation inside a flash loan
		callbackPatterns: []*regexp.Regexp{
			// EIP-3156: receiver.onFlashLoan(...)
			regexp.MustCompile(`\breceiver\b.*\.onFlashLoan\s*\(`),
			// Aave: receiver.executeOperation(...)
			regexp.MustCompile(`\breceiver\b.*\.executeOperation\s*\(`),
			// Generic: IFlashBorrower(x).onFlashLoan(...)
			regexp.MustCompile(`IFlash\w*\s*\(\s*\w+\s*\)\s*\.\s*on\w+\s*\(`),
			// Generic: borrower.onFlashLoan / borrower.execute
			regexp.MustCompile(`\bborrower\b.*\.\s*(?:onFlashLoan|execute\w*)\s*\(`),
			// Any user-provided address callback. This is conservative and
			// lower confidence when only a generic callback shape is present.
			regexp.MustCompile(`\b\w+\s*\.\s*(?:onFlashLoan|executeOperation|flashCallback)\s*\(`),
		},

		// Standard flash loan receiver callback function names
		receiverFuncNames: regexp.MustCompile(
			`^\s*function\s+(` +
				`onFlashLoan|` + // EIP-3156
				`executeOperation|` + // Aave V2/V3
				`uniswapV2Call|` + // Uniswap V2
				`uniswapV3FlashCallback|` + // Uniswap V3
				`pancakeCall|` + // PancakeSwap
				`BiswapCall|` + // Biswap
				`sushiCall|` + // SushiSwap
				`DVMFlashLoanCall|` + // DODO
				`DPPFlashLoanCall` + // DODO V2
				`)\s*\(`,
		),

		// Patterns that verify msg.sender in a callback
		callerVerification: []*regexp.Regexp{
			regexp.MustCompile(`require\s*\(\s*msg\.sender\s*==\s*\w`),
			regexp.MustCompile(`require\s*\(\s*msg\.sender\s*==\s*address\s*\(`),
			regexp.MustCompile(`if\s*\(\s*msg\.sender\s*!=\s*\w+.*\)\s*(?:revert|return)`),
			regexp.MustCompile(`_(?:allowed|trusted|valid)\w*\[\s*msg\.sender\s*\]`),
		},

		reentrancyGuards: regexp.MustCompile(
			`\b(nonReentrant|nonreentrant|lock|noReentrant|reentrancyGuard)\b`,
		),

		stateWritePatterns: []*regexp.Regexp{
			// mapping or array write
			regexp.MustCompile(`\b\w+\s*\[\s*\w+\s*\]\s*(?:[+\-*/]=|=[^=])`),
			regexp.MustCompile(`\b_\w+\s*(?:[+\-*/]=|=[^=])`),
			regexp.MustCompile(`\btotal\w+\s*(?:[+\-*/]=)`),
			regexp.MustCompile(`\b(?:balance|reserve|supply|borrow|debt)\w*\s*(?:[+\-*/]=)`),
		},
	}
}

func (d *FlashLoanDetector) Name() string                { return "flash-loan" }
func (d *FlashLoanDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *FlashLoanDetector) Description() string {
	return "Detects flash loan providers missing reentrancy guards and receivers missing caller verification"
}

func (d *FlashLoanDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	fns := extractFunctions(lines)
	var findings []analyzer.Finding

	for _, fn := range fns {
		// Check both patterns for each function
		if finding := d.checkProvider(fn, filepath); finding != nil {
			findings = append(findings, *finding)
		}
		if finding := d.checkReceiver(fn, filepath); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// Pattern 1: Flash loan provider.

// checkProvider detects flash loan functions that are missing reentrancy
// protection while writing state around a user-controlled callback.
func (d *FlashLoanDetector) checkProvider(fn *fnBlock, filepath string) *analyzer.Finding {
	if !d.providerFuncNames.MatchString("function " + fn.name + "(") {
		return nil
	}
	if fn.visibility == "internal" || fn.visibility == "private" {
		return nil
	}

	// Find the callback invocation in the function body
	callbackLine, callbackSnippet := d.findCallback(fn)
	if callbackLine < 0 {
		return nil
	}

	if d.isStandardFlashMint(fn) {
		return nil
	}

	// Already protected by a reentrancy guard?
	if d.hasReentrancyGuard(fn) {
		return nil
	}
	if d.hasMutexInBody(fn) {
		return nil
	}

	// Classify severity: does the function write state around the callback?
	severity, stateSnippet := d.classifyProviderSeverity(fn, callbackLine)

	desc := "Function '" + fn.name + "' invokes a user-controlled callback (" +
		callbackSnippet + ") without a reentrancy guard."
	if stateSnippet != "" {
		desc += "\n\nState is written before or after the callback:\n  " + stateSnippet +
			"\n\nDuring the callback, protocol state is inconsistent. An attacker " +
			"can exploit this window by re-entering other protocol functions."
	} else {
		desc += "\n\nEven without adjacent state writes, the callback creates a " +
			"reentrancy window that can be exploited in combination with other functions."
	}

	finding := detectorFinding(rules.IDDefi001, filepath, fn.startLine, callbackSnippet)
	finding.Title = "Flash loan '" + fn.name + "' missing reentrancy guard"
	finding.Description = desc
	finding.Confidence = analyzer.ConfidenceHigh
	finding.Severity = severity
	return &finding
}

func (d *FlashLoanDetector) isStandardFlashMint(fn *fnBlock) bool {
	body := strings.Join(fn.lines, "\n")
	standardSignals := []*regexp.Regexp{
		regexp.MustCompile(`IERC3156FlashBorrower\s*\(`),
		regexp.MustCompile(`\.onFlashLoan\s*\(`),
		regexp.MustCompile(`RETURN_VALUE`),
		regexp.MustCompile(`\bflashFee\s*\(`),
		regexp.MustCompile(`\bmaxFlashLoan\s*\(`),
		regexp.MustCompile(`_mint\s*\(`),
		regexp.MustCompile(`_burn\s*\(`),
		regexp.MustCompile(`_spendAllowance\s*\(`),
	}

	matches := 0
	for _, p := range standardSignals {
		if p.MatchString(body) {
			matches++
		}
	}
	if matches < 4 {
		return false
	}

	repaymentPatterns := []*regexp.Regexp{
		regexp.MustCompile(`_spendAllowance\s*\(`),
		regexp.MustCompile(`\.transferFrom\s*\(`),
		regexp.MustCompile(`_burn\s*\(`),
		regexp.MustCompile(`require\s*\(.*(?:amount|fee|repay|repayment)`),
	}
	for _, p := range repaymentPatterns {
		if p.MatchString(body) {
			return true
		}
	}
	return false
}

func (d *FlashLoanDetector) findCallback(fn *fnBlock) (int, string) {
	for i, line := range fn.lines {
		for _, p := range d.callbackPatterns {
			if p.MatchString(line) {
				return i, strings.TrimSpace(line)
			}
		}
	}
	return -1, ""
}

func (d *FlashLoanDetector) hasReentrancyGuard(fn *fnBlock) bool {
	for _, line := range fn.lines {
		if d.reentrancyGuards.MatchString(line) {
			return true
		}
		if strings.Contains(line, "{") {
			break
		}
	}
	return false
}

func (d *FlashLoanDetector) classifyProviderSeverity(
	fn *fnBlock,
	callbackLine int,
) (analyzer.Severity, string) {

	// Check for state writes before the callback
	for i := 0; i < callbackLine && i < len(fn.lines); i++ {
		line := fn.lines[i]
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, p := range d.stateWritePatterns {
			if p.MatchString(line) {
				return analyzer.Critical, strings.TrimSpace(line)
			}
		}
	}

	// Check for state writes after the callback
	for i := callbackLine + 1; i < len(fn.lines); i++ {
		line := fn.lines[i]
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, p := range d.stateWritePatterns {
			if p.MatchString(line) {
				return analyzer.Critical, strings.TrimSpace(line)
			}
		}
	}

	// No state writes found; still a concern, but lower severity.
	return analyzer.High, ""
}

func (d *FlashLoanDetector) hasMutexInBody(fn *fnBlock) bool {
	mutexRe := regexp.MustCompile(
		`require\s*\(\s*!\s*_?(?:locked|entered|mutex)\b|` +
			`_?(?:locked|entered|mutex)\s*=\s*true`,
	)
	for _, line := range fn.lines {
		if mutexRe.MatchString(line) {
			return true
		}
	}
	return false
}

// Pattern 2: Flash loan receiver.

// checkReceiver detects flash loan callback functions that do not verify
// the caller's identity, allowing anyone to call them directly.
func (d *FlashLoanDetector) checkReceiver(fn *fnBlock, filepath string) *analyzer.Finding {
	// Must be a standard flash loan callback name
	if !d.receiverFuncNames.MatchString("function " + fn.name + "(") {
		return nil
	}
	if fn.visibility == "internal" || fn.visibility == "private" {
		return nil
	}
	if len(fn.lines) <= 2 {
		return nil
	}

	// Does the callback verify the caller?
	if d.hasCallerVerification(fn) {
		return nil
	}

	// What does the callback do? Severity based on body content.
	severity, bodySnippet := d.classifyReceiverSeverity(fn)
	if severity == analyzer.Info {
		return nil // Too minimal to flag
	}

	finding := detectorFinding(
		rules.IDDefi002,
		filepath,
		fn.startLine,
		"function "+fn.name+"(...) external { ... }",
	)
	finding.Title = "Flash loan callback '" + fn.name + "' missing caller verification"
	finding.Description = "'" + fn.name + "' does not verify that msg.sender is a trusted lender. " +
		"Anyone can call this function directly with crafted parameters, " +
		"executing callback logic outside of a legitimate flash loan.\n\n" +
		"Per EIP-3156, receivers must check:\n" +
		"  require(msg.sender == address(lender), \"untrusted lender\");\n" +
		"  require(initiator == address(this), \"untrusted initiator\");\n\n" +
		"Body operation detected:\n  " + bodySnippet
	finding.Confidence = analyzer.ConfidenceHigh
	finding.Severity = severity
	return &finding
}

func (d *FlashLoanDetector) hasCallerVerification(fn *fnBlock) bool {
	// Check the first 8 lines of the body for caller verification
	inBody := false
	checked := 0

	for _, line := range fn.lines {
		if !inBody {
			if strings.Contains(line, "{") {
				inBody = true
			}
			continue
		}
		checked++
		if checked > 8 {
			break
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, p := range d.callerVerification {
			if p.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func (d *FlashLoanDetector) classifyReceiverSeverity(
	fn *fnBlock,
) (analyzer.Severity, string) {

	// HIGH indicators: token operations, approvals, privileged calls
	highPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\.transfer\s*\(|\.transferFrom\s*\(|\.safeTransfer\s*\(`),
		regexp.MustCompile(`\.approve\s*\(|\.safeApprove\s*\(`),
		regexp.MustCompile(`\.mint\s*\(|\.burn\s*\(`),
		regexp.MustCompile(`\.call\s*\{|\.call\s*\(`),
	}

	for _, line := range fn.lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, p := range highPatterns {
			if p.MatchString(line) {
				return analyzer.High, trimmed
			}
		}

		for _, p := range d.stateWritePatterns {
			if p.MatchString(line) {
				return analyzer.High, trimmed
			}
		}
	}

	// Minimal body is not worth flagging.
	return analyzer.Info, ""
}

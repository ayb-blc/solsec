// internal/detectors/signature_replay.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// SignatureReplayDetector finds ecrecover() usage that is missing
// replay protection: nonce, chainID, or deadline.
//
// Severity:
//
//	CRITICAL - no nonce AND no chainID
//	HIGH     - no nonce (same-chain replay trivially possible)
//	MEDIUM   - no chainID only (cross-chain replay)
//	LOW      - no deadline only (signature never expires)
//
// Safe patterns (skipped):
//
//	_hashTypedDataV4()     - OZ EIP-712, chainID in domain separator
//	DOMAIN_SEPARATOR       - EIP-712 domain includes chainID
//	ERC20Permit / EIP2612  - standardized, always correct
type SignatureReplayDetector struct {
	ecrecoverRe *regexp.Regexp

	safeHelpers []*regexp.Regexp

	noncePatterns []*regexp.Regexp

	chainIDPatterns []*regexp.Regexp

	deadlinePatterns []*regexp.Regexp

	skipFuncNames *regexp.Regexp
}

func NewSignatureReplayDetector() *SignatureReplayDetector {
	return &SignatureReplayDetector{

		ecrecoverRe: regexp.MustCompile(`\becrecover\s*\(`),

		// If any of these exist in the function, chainID is covered.
		// These are EIP-712 patterns that include chainID in the domain.
		safeHelpers: []*regexp.Regexp{
			// OZ: _hashTypedDataV4 uses EIP-712 domain with chainID.
			regexp.MustCompile(`_hashTypedDataV4\s*\(`),
			// DOMAIN_SEPARATOR usage typically includes chainID.
			regexp.MustCompile(`\bDOMAIN_SEPARATOR\b`),
			// OZ helper
			regexp.MustCompile(`_domainSeparatorV4\s*\(\s*\)`),
			// Direct use of domainSeparator() or _domainSeparator()
			regexp.MustCompile(`\bdomainSeparator\s*\(\s*\)`),
		},

		noncePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bnonces\s*\[`),
			regexp.MustCompile(`_useNonce\s*\(`),
			regexp.MustCompile(`\bnonce\b.*(?:\+\+|\+=)`),
			regexp.MustCompile(`\bnonce\b`),
			regexp.MustCompile(`_nonces\s*\[`),
			regexp.MustCompile(`\w*[Nn]once\w*\s*(?:\+\+|\+=|\[)`),
		},

		chainIDPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bblock\.chainid\b`),
			regexp.MustCompile(`\bblock\.chainId\b`),
			regexp.MustCompile(`\bchainId\b`),
			regexp.MustCompile(`\bchainID\b`),
			regexp.MustCompile(`assembly.*chainid`),
		},

		deadlinePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bdeadline\b`),
			regexp.MustCompile(`\bexpiry\b`),
			regexp.MustCompile(`\bexpiration\b`),
			regexp.MustCompile(`block\.timestamp\s*[<>]=?\s*\w`),
			regexp.MustCompile(`require.*(?:deadline|expir)`),
		},

		// Skip helpers that are unlikely to be vulnerable or are view-only.
		skipFuncNames: regexp.MustCompile(
			`^\s*function\s+(?:` +
				`getEthSignedMessageHash|` +
				`toEthSignedMessageHash|` +
				`tryRecover|` +
				`recover|` +
				`getSigner|` +
				`recoverSigner|` +
				`verify\b|` +
				`isValid\w*Signature` +
				`)\s*\(`,
		),
	}
}

func (d *SignatureReplayDetector) Name() string                { return "signature-replay" }
func (d *SignatureReplayDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *SignatureReplayDetector) Description() string {
	return "Detects ecrecover() usage missing nonce, chainID, or deadline"
}

func (d *SignatureReplayDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	if isSolidityLibrary(source) {
		return nil, nil
	}

	fns := extractFunctions(lines)
	var findings []analyzer.Finding

	for _, fn := range fns {
		if d.skipFuncNames.MatchString("function " + fn.name + "(") {
			continue
		}
		if fn.mutability == "view" || fn.mutability == "pure" {
			continue
		}
		if fn.visibility == "internal" || fn.visibility == "private" {
			continue
		}
		if !d.hasAuthorizationUse(fn) {
			continue
		}

		if !d.usesEcrecover(fn) {
			continue
		}

		funcText := strings.Join(fn.lines, "\n")

		hasEIP712 := d.hasEIP712Helper(funcText)

		hasNonce := d.hasNonce(funcText)
		hasChainID := hasEIP712 || d.hasChainID(funcText)
		hasDeadline := d.hasDeadline(funcText)

		if hasNonce && hasChainID && hasDeadline {
			continue
		}
		// Only deadline missing is a LOW informational finding.
		if hasNonce && hasChainID && !hasDeadline {
			finding := d.buildFinding(
				fn, filepath,
				analyzer.Low,
				"no deadline",
				"The signed message has no expiry. A valid signature remains usable forever. "+
					"Consider adding a 'deadline' field: require(block.timestamp <= deadline).",
				analyzer.ConfidenceLow,
			)
			findings = append(findings, finding)
			continue
		}

		// Determine main severity based on what's missing.
		severity, missingDesc, detail := d.classifySeverity(
			hasNonce, hasChainID,
		)

		finding := d.buildFinding(fn, filepath, severity, missingDesc, detail,
			analyzer.ConfidenceHigh)
		findings = append(findings, finding)
	}

	return findings, nil
}

func isSolidityLibrary(source string) bool {
	hasLibrary := regexp.MustCompile(`(?m)^\s*library\s+\w+`).MatchString(source)
	hasContract := regexp.MustCompile(`(?m)^\s*(?:abstract\s+)?contract\s+\w+`).MatchString(source)
	return hasLibrary && !hasContract
}

func (d *SignatureReplayDetector) usesEcrecover(fn *fnBlock) bool {
	for _, line := range fn.lines {
		if d.ecrecoverRe.MatchString(line) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) hasAuthorizationUse(fn *fnBlock) bool {
	text := strings.Join(fn.lines, "\n")
	authPatterns := []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(.*(?:signer|recovered|account|owner|user|from).*==`),
		regexp.MustCompile(`if\s*\(.*(?:signer|recovered|account|owner|user|from).*!?=`),
		regexp.MustCompile(`\b(?:owner|admin|operator|authorized|approved)\s*=`),
		regexp.MustCompile(`\b(?:transfer|transferFrom|safeTransferFrom|approve|permit|mint|burn)\s*\(`),
		regexp.MustCompile(`\b(?:_transfer|_approve|_mint|_burn|_grantRole|grantRole)\s*\(`),
	}
	for _, p := range authPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) hasEIP712Helper(text string) bool {
	for _, p := range d.safeHelpers {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) hasNonce(text string) bool {
	for _, p := range d.noncePatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) hasChainID(text string) bool {
	for _, p := range d.chainIDPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) hasDeadline(text string) bool {
	for _, p := range d.deadlinePatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *SignatureReplayDetector) classifySeverity(
	hasNonce, hasChainID bool,
) (analyzer.Severity, string, string) {

	switch {
	case !hasNonce && !hasChainID:
		return analyzer.Critical,
			"no nonce, no chainID",
			"The signed hash includes neither a nonce nor a chainID. " +
				"An attacker who observes this signature can:\n" +
				"  1. Replay it on the same chain indefinitely\n" +
				"  2. Replay it on any other chain (fork, testnet, L2)"

	case !hasNonce:
		return analyzer.High,
			"no nonce",
			"The signed hash has no nonce. Once a user signs a message, " +
				"anyone who sees that signature can replay it on this chain " +
				"as many times as they want."

	case !hasChainID:
		return analyzer.Medium,
			"no chainID",
			"The signed hash has no chainID. This signature can be replayed " +
				"on any chain that runs this contract " +
				"(mainnet fork, testnet, L2 deployment)."

	default:
		return analyzer.Low,
			"no deadline",
			"The signed message has no expiry."
	}
}

func (d *SignatureReplayDetector) buildFinding(
	fn *fnBlock,
	filepath string,
	severity analyzer.Severity,
	missingDesc string,
	detail string,
	confidence analyzer.Confidence,
) analyzer.Finding {

	finding := detectorFinding(rules.IDDefi003, filepath, fn.startLine, "ecrecover(hash, v, r, s)")
	finding.Title = "Signature replay in '" + fn.name + "' - " + missingDesc
	finding.Description = "Function '" + fn.name + "' uses ecrecover() but the signed " +
		"message is missing: " + missingDesc + ".\n\n" + detail
	finding.Confidence = confidence
	finding.Severity = severity
	return finding
}

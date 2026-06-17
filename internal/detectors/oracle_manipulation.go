// internal/detectors/oracle_manipulation.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// OracleManipulationDetector finds unsafe oracle usage patterns:
//
//  1. AMM spot price via getReserves() — CRITICAL (flash loan manipulable)
//  2. Chainlink without staleness check — HIGH
//  3. Chainlink without answer validity — HIGH
//  4. Single oracle with no fallback — MEDIUM
type OracleManipulationDetector struct {
	// ── AMM spot price patterns ─────────────────────────────────────

	// getReserves() call — the primary signal for AMM spot price usage
	getReservesRe *regexp.Regexp

	// Price calculation directly from reserves
	reservePriceCalcRe *regexp.Regexp

	// ── Chainlink patterns ───────────────────────────────────────────

	// latestRoundData() call
	latestRoundDataRe *regexp.Regexp

	// latestAnswer() — deprecated but still used (no staleness info)
	latestAnswerRe *regexp.Regexp

	// ── Safe patterns — presence of any → protected ──────────────────

	// TWAP patterns (safe alternatives to spot price)
	twapPatterns []*regexp.Regexp

	// Staleness check patterns for Chainlink
	stalenessPatterns []*regexp.Regexp

	// Answer validity check (price > 0)
	validityPatterns []*regexp.Regexp

	// Multi-oracle patterns (median, average of multiple sources)
	multiOraclePatterns []*regexp.Regexp

	// L2 sequencer uptime/status feeds use latestRoundData(), but answer is a
	// status bit rather than a price. Price validity/staleness rules do not
	// apply to those functions.
	sequencerUptimePatterns []*regexp.Regexp
}

func NewOracleManipulationDetector() *OracleManipulationDetector {
	return &OracleManipulationDetector{

		// getReserves() — Uniswap V2 / compatible AMM
		getReservesRe: regexp.MustCompile(
			`\.getReserves\s*\(\s*\)`,
		),

		// Price calculated from reserves: r1/r0, reserve0*x/reserve1, etc.
		reservePriceCalcRe: regexp.MustCompile(
			`\breserve[01]?\b.*[/*].*\breserve[01]?\b|` +
				`\b_?reserve\d*\s*[/*]\s*_?reserve\d*|` +
				`\br[01]\b.*[/*].*\br[01]\b`,
		),

		// Chainlink: AggregatorV3Interface.latestRoundData()
		latestRoundDataRe: regexp.MustCompile(
			`\.latestRoundData\s*\(\s*\)`,
		),

		// Deprecated Chainlink: latestAnswer()
		latestAnswerRe: regexp.MustCompile(
			`\.latestAnswer\s*\(\s*\)`,
		),

		// ── Safe patterns ─────────────────────────────────────────────

		twapPatterns: []*regexp.Regexp{
			// Uniswap V3: pool.observe(secondsAgos)
			regexp.MustCompile(`\.observe\s*\(`),
			// Uniswap V3: OracleLibrary.consult(...)
			regexp.MustCompile(`OracleLibrary\s*\.\s*consult\s*\(`),
			// Uniswap V2: price0/1CumulativeLast (TWAP oracle)
			regexp.MustCompile(`price[01]CumulativeLast`),
			// Generic TWAP reference
			regexp.MustCompile(`\bTWAP\b|\btwap\b`),
			// Uniswap V2 oracle pattern: currentCumulativePrice
			regexp.MustCompile(`currentCumulativePrice|cumulativePrice`),
			// Time-weighted average
			regexp.MustCompile(`timeWeighted|time_weighted`),
		},

		// Staleness check patterns — presence = Chainlink used safely
		stalenessPatterns: []*regexp.Regexp{
			// updatedAt >= block.timestamp - X (most common)
			regexp.MustCompile(
				`updatedAt\s*>=?\s*block\.timestamp\s*-`,
			),
			// block.timestamp - updatedAt <= X
			regexp.MustCompile(
				`block\.timestamp\s*-\s*updatedAt\s*<=?`,
			),
			// Named constants for max staleness
			regexp.MustCompile(
				`(?i)(?:MAX_DELAY|HEARTBEAT|STALE_PERIOD|ORACLE_TIMEOUT|` +
					`MAX_STALENESS|PRICE_STALENESS_THRESHOLD|FRESHNESS)`,
			),
			// answeredInRound >= roundId (round completeness check)
			regexp.MustCompile(
				`answeredInRound\s*>=?\s*roundId`,
			),
		},

		// Answer validity check
		validityPatterns: []*regexp.Regexp{
			// require(price > 0) or require(answer > 0)
			regexp.MustCompile(
				`require\s*\(\s*(?:price|answer|_price|_answer)\s*>\s*0`,
			),
			// if (price <= 0) revert
			regexp.MustCompile(
				`if\s*\(\s*(?:price|answer)\s*<=?\s*0\s*\)\s*revert`,
			),
			// price must be positive (named check)
			regexp.MustCompile(
				`(?i)invalid.*price|price.*invalid|` +
					`negative.*price|price.*negative`,
			),
		},

		// Multi-oracle patterns
		multiOraclePatterns: []*regexp.Regexp{
			// Using median or average across oracles
			regexp.MustCompile(`(?i)median|average.*oracle|oracle.*average`),
			// Multiple oracle sources
			regexp.MustCompile(`oracle[12]|_oracle[12]|priceFeed[12]`),
			// Band Protocol alongside Chainlink
			regexp.MustCompile(`\bIStdReference\b|\bBandOracle\b`),
		},

		sequencerUptimePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)sequencer|uptime|grace\s*period|gracePeriod`),
			regexp.MustCompile(`(?i)isUpAndGracePeriodPassed|isBorrowAllowed|isLiquidationAllowed`),
			regexp.MustCompile(`(?i)lastUpdateTimestamp`),
			regexp.MustCompile(`\banswer\s*(?:==|!=)\s*[01]\b`),
		},
	}
}

func (d *OracleManipulationDetector) Name() string                { return "oracle-manipulation" }
func (d *OracleManipulationDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *OracleManipulationDetector) Description() string {
	return "Detects spot price oracles (AMM) and Chainlink feeds missing freshness validation"
}

func (d *OracleManipulationDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	fns := extractFunctions(lines)
	var findings []analyzer.Finding
	cleanSource := stripOracleLineComments(source)

	for _, fn := range fns {
		// Skip internal pure/view helpers — they don't make protocol decisions
		if fn.visibility == "internal" || fn.visibility == "private" {
			if fn.mutability == "pure" {
				continue
			}
		}

		funcText := stripOracleLineComments(strings.Join(fn.lines, "\n"))

		// Check each oracle pattern category
		if finding := d.checkAMMSpotPrice(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
		}
		if finding := d.checkChainlinkStaleness(fn, funcText, cleanSource, filepath); finding != nil {
			findings = append(findings, *finding)
		}
		if finding := d.checkChainlinkValidity(fn, funcText, cleanSource, filepath); finding != nil {
			findings = append(findings, *finding)
		}
		if finding := d.checkLatestAnswer(fn, funcText, filepath); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// ── Check 1: AMM Spot Price ───────────────────────────────────────────────────

// checkAMMSpotPrice flags functions that read AMM reserves and use them
// as a price source without TWAP protection.
func (d *OracleManipulationDetector) checkAMMSpotPrice(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.getReservesRe.MatchString(funcText) {
		return nil
	}

	// Does the function use reserves for pricing?
	// (as opposed to just reading liquidity for some other purpose)
	usedForPrice := d.reservePriceCalcRe.MatchString(funcText) ||
		strings.Contains(funcText, "reserve") &&
			(strings.Contains(funcText, "price") ||
				strings.Contains(funcText, "value") ||
				strings.Contains(funcText, "worth") ||
				strings.Contains(funcText, "amount"))

	if !usedForPrice {
		return nil
	}

	// Is it using a TWAP instead? (safe)
	if d.hasTWAP(funcText) {
		return nil
	}

	// Extract the getReserves line for the snippet
	snippet := extractMatchingLine(fn.lines, d.getReservesRe)
	finding := detectorFinding(rules.IDDefi005, filepath, fn.startLine, snippet)
	finding.Title = "AMM spot price in '" + fn.name + "' - manipulable via flash loan"
	finding.Description = "'" + fn.name + "' reads AMM reserves via getReserves() and uses the " +
		"result as a price feed. AMM spot prices can be manipulated in a single " +
		"transaction using flash loans.\n\n" +
		"getReserves() returns instantaneous reserves; an attacker can:\n" +
		"  1. Flash-loan a large amount of token\n" +
		"  2. Swap in the AMM pool and change reserves\n" +
		"  3. Call your protocol with the manipulated price\n" +
		"  4. Repay the flash loan in the same transaction\n\n" +
		"Fix: use a TWAP oracle such as Uniswap V3 pool.observe(), or Uniswap V2 " +
		"price0CumulativeLast with a 30+ minute window."
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.Critical
	return &finding
}

// ── Check 2: Chainlink Staleness ─────────────────────────────────────────────

// checkChainlinkStaleness flags latestRoundData() calls that don't
// verify the updatedAt timestamp.
func (d *OracleManipulationDetector) checkChainlinkStaleness(
	fn *fnBlock,
	funcText string,
	contractSource string,
	filepath string,
) *analyzer.Finding {

	if !d.latestRoundDataRe.MatchString(funcText) {
		return nil
	}
	if d.isSequencerUptimeFeed(funcText) {
		return nil
	}

	// Check staleness guard in this function AND contract scope
	// (guard might be in a wrapper or modifier)
	hasStalenessCheck := d.hasPattern(funcText, d.stalenessPatterns) ||
		d.hasPattern(contractSource, d.stalenessPatterns)

	if hasStalenessCheck {
		return nil
	}

	snippet := extractMatchingLine(fn.lines, d.latestRoundDataRe)
	finding := detectorFinding(rules.IDDefi005, filepath, fn.startLine, snippet)
	finding.Title = "Chainlink oracle in '" + fn.name + "' missing staleness check"
	finding.Description = "'" + fn.name + "' calls latestRoundData() but does not validate " +
		"the updatedAt timestamp. Chainlink oracles can pause during extreme " +
		"market conditions, returning a price that is hours or days old.\n\n" +
		"A stale price can cause incorrect collateral valuation, wrong liquidation " +
		"thresholds, or price arbitrage against the protocol.\n\n" +
		"Fix:\n" +
		"  require(updatedAt >= block.timestamp - MAX_DELAY, \"Stale price\");\n" +
		"  require(answeredInRound >= roundId, \"Incomplete round\");"
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.High
	return &finding
}

// ── Check 3: Chainlink Answer Validity ───────────────────────────────────────

// checkChainlinkValidity flags latestRoundData() calls that don't
// check if the returned price is positive.
func (d *OracleManipulationDetector) checkChainlinkValidity(
	fn *fnBlock,
	funcText string,
	contractSource string,
	filepath string,
) *analyzer.Finding {

	if !d.latestRoundDataRe.MatchString(funcText) {
		return nil
	}
	if d.isSequencerUptimeFeed(funcText) {
		return nil
	}

	// Check validity guard in function or contract scope
	hasValidityCheck := d.hasPattern(funcText, d.validityPatterns) ||
		d.hasPattern(contractSource, d.validityPatterns)

	if hasValidityCheck {
		return nil
	}

	// Avoid duplicate: only flag validity if staleness was already
	// flagged in the same function (both are HIGH, pick the more severe)
	// Or flag both — they are independent issues.
	// For simplicity: flag validity separately.

	snippet := extractMatchingLine(fn.lines, d.latestRoundDataRe)
	finding := detectorFinding(rules.IDDefi005, filepath, fn.startLine, snippet)
	finding.Title = "Chainlink oracle in '" + fn.name + "' missing answer validity check"
	finding.Description = "'" + fn.name + "' calls latestRoundData() but does not verify that " +
		"the returned price is positive. Chainlink can return 0 or a negative " +
		"value during circuit breaker events.\n\n" +
		"A 0 or negative price can cause division errors, unsafe uint256 casts, " +
		"or inflated borrow limits.\n\n" +
		"Fix:\n" +
		"  (, int256 price, , uint256 updatedAt,) = feed.latestRoundData();\n" +
		"  require(price > 0, \"Invalid price\");"
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.High
	return &finding
}

// ── Check 4: Deprecated latestAnswer() ───────────────────────────────────────

// checkLatestAnswer flags use of the deprecated latestAnswer() function.
// It provides no round data, so staleness cannot be checked.
func (d *OracleManipulationDetector) checkLatestAnswer(
	fn *fnBlock,
	funcText string,
	filepath string,
) *analyzer.Finding {

	if !d.latestAnswerRe.MatchString(funcText) {
		return nil
	}

	snippet := extractMatchingLine(fn.lines, d.latestAnswerRe)
	finding := detectorFinding(rules.IDDefi005, filepath, fn.startLine, snippet)
	finding.Title = "Deprecated Chainlink latestAnswer() in '" + fn.name + "'"
	finding.Description = "'" + fn.name + "' uses latestAnswer() which is deprecated by Chainlink. " +
		"This function provides no round information, making it impossible to " +
		"check for stale data or incomplete rounds.\n\n" +
		"Fix: migrate to latestRoundData() with full validation:\n" +
		"  (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound)\n" +
		"      = priceFeed.latestRoundData();"
	finding.Confidence = analyzer.ConfidenceHigh

	finding.Severity = analyzer.High
	return &finding
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (d *OracleManipulationDetector) hasTWAP(text string) bool {
	for _, p := range d.twapPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *OracleManipulationDetector) hasPattern(text string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func (d *OracleManipulationDetector) isSequencerUptimeFeed(funcText string) bool {
	if !d.latestRoundDataRe.MatchString(funcText) {
		return false
	}
	return d.hasPattern(funcText, d.sequencerUptimePatterns)
}

// extractMatchingLine returns the first line matching re, trimmed.
func extractMatchingLine(lines []string, re *regexp.Regexp) string {
	for _, line := range lines {
		if re.MatchString(line) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func stripOracleLineComments(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

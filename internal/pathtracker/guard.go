// internal/pathtracker/guard.go

package pathtracker

import (
	"regexp"
	"strings"
)

type guardScanner struct {
	// Access control: require(msg.sender == X) or if (msg.sender != X) revert
	msgSenderEqRe  *regexp.Regexp
	msgSenderNeqRe *regexp.Regexp
	mappingCheckRe *regexp.Regexp
	roleCheckRe    *regexp.Regexp

	// Reentrancy: require(!_locked), require(_status == NOT_ENTERED)
	reentrancyRe *regexp.Regexp

	// Pause: require(!paused())
	pausedRe *regexp.Regexp

	// Initialized: require(!_initialized), require(initialized)
	initializedRe *regexp.Regexp

	// Generic: require(...) or if (...) revert/return
	genericRequireRe *regexp.Regexp
	ifRevertRe       *regexp.Regexp
}

func newGuardScanner() *guardScanner {
	return &guardScanner{
		msgSenderEqRe: regexp.MustCompile(
			`require\s*\(\s*msg\.sender\s*==\s*\w`,
		),
		msgSenderNeqRe: regexp.MustCompile(
			`if\s*\(\s*msg\.sender\s*!=\s*\w+.*\)\s*(?:revert|return)`,
		),
		mappingCheckRe: regexp.MustCompile(
			`require\s*\(\s*(?:isAdmin|isOwner|isOperator|whitelist|authorized)\s*\[`,
		),
		roleCheckRe: regexp.MustCompile(
			`require\s*\(\s*hasRole\s*\(|_checkRole\s*\(`,
		),
		reentrancyRe: regexp.MustCompile(
			`require\s*\(\s*!\s*_?(?:locked|entered|reentrancyGuard|mutex)\b|` +
				`_status\s*==\s*_NOT_ENTERED|` +
				`if\s*\(\s*_?(?:locked|entered)\s*\)\s*revert`,
		),
		pausedRe: regexp.MustCompile(
			`require\s*\(\s*!?\s*(?:_?paused\s*\(\s*\)|_paused)\b`,
		),
		initializedRe: regexp.MustCompile(
			`require\s*\(\s*!\s*_?initialized\b|` +
				`require\s*\(\s*!\s*_?isInitialized\b|` +
				`if\s*\(\s*_?initialized\b.*\)\s*(?:revert|return)`,
		),
		genericRequireRe: regexp.MustCompile(`^\s*require\s*\(`),
		ifRevertRe: regexp.MustCompile(
			`^\s*if\s*\(.*\)\s*(?:revert|return)\b`,
		),
	}
}

// scan returns all guards found in the first maxLines of bodyLines.
// Stops scanning once it encounters a state write or external call
// (at that point, we're past the "guard zone").
func (s *guardScanner) scan(bodyLines []string, maxLines int) []EarlyGuard {
	var guards []EarlyGuard
	depth := 0

	for i, line := range bodyLines {
		if i >= maxLines {
			break
		}
		trimmed := strings.TrimSpace(line)

		// Track brace depth — only scan top-level guards
		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}

		// Skip comments and blank lines
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Stop at external calls or state writes in the body —
		// we've moved past the guard zone.
		if depth == 0 && isStateWriteOrCall(trimmed) {
			break
		}

		g := s.matchGuard(trimmed, i)
		if g != nil {
			guards = append(guards, *g)
		}
	}

	return guards
}

func (s *guardScanner) matchGuard(line string, lineIdx int) *EarlyGuard {
	lineNum := lineIdx + 1

	// Access control patterns
	if s.msgSenderEqRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardAccessControl,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}
	if s.msgSenderNeqRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardAccessControl,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}
	if s.mappingCheckRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardAccessControl,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}
	if s.roleCheckRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardAccessControl,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}

	// Reentrancy guard
	if s.reentrancyRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardReentrancy,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}

	// Pause guard
	if s.pausedRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardPaused,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}

	// Initialization guard
	if s.initializedRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardInitialized,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}

	// Generic require / if+revert
	if s.genericRequireRe.MatchString(line) || s.ifRevertRe.MatchString(line) {
		return &EarlyGuard{
			Kind:      GuardOther,
			Condition: extractCondition(line),
			Line:      line,
			LineNum:   lineNum,
		}
	}

	return nil
}

// isStateWriteOrCall is a quick heuristic to detect body operations
// that end the "guard zone".
func isStateWriteOrCall(line string) bool {
	// External call
	if regexp.MustCompile(`\.\s*call\s*\{|\.\s*transfer\s*\(|\.\s*send\s*\(`).MatchString(line) {
		return true
	}
	// State write (simple assignment not inside require/if condition)
	if regexp.MustCompile(`^\s*\w+\s*(?:\[.*\]\s*)?[+\-*/]?=\s*[^=]`).MatchString(line) &&
		!strings.HasPrefix(strings.TrimSpace(line), "require") &&
		!strings.HasPrefix(strings.TrimSpace(line), "if") {
		return true
	}
	return false
}

func extractCondition(line string) string {
	// Extract content between first ( and matching )
	start := strings.Index(line, "(")
	if start < 0 {
		return strings.TrimSpace(line)
	}
	depth := 0
	for i := start; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(line[start+1 : i])
			}
		}
	}
	return strings.TrimSpace(line)
}

// internal/pathtracker/branch.go

package pathtracker

import (
	"regexp"
	"strings"
)

type branchScanner struct {
	ifStartRe     *regexp.Regexp
	elseRe        *regexp.Regexp
	condExtractRe *regexp.Regexp
}

func newBranchScanner() *branchScanner {
	return &branchScanner{
		ifStartRe:     regexp.MustCompile(`^\s*if\s*\(`),
		elseRe:        regexp.MustCompile(`^\s*}\s*else\s*(?:\{|if\s*\()`),
		condExtractRe: regexp.MustCompile(`^\s*if\s*\(`),
	}
}

// contextAt returns the branch context at the given line offset within bodyLines.
// It tracks brace depth and if-condition stack to determine what conditions
// enclose that line.
func (s *branchScanner) contextAt(bodyLines []string, targetOffset int) *BranchContext {
	if targetOffset < 0 || targetOffset >= len(bodyLines) {
		return nil
	}

	type frame struct {
		condition string
		depth     int
		lineNum   int
		isNegated bool // true if we're in an else branch
	}

	var stack []frame
	depth := 0

	for i := 0; i < targetOffset; i++ {
		line := bodyLines[i]
		trimmed := strings.TrimSpace(line)

		// Count braces
		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				// Pop stack frames that are deeper than current depth
				for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
					stack = stack[:len(stack)-1]
				}
			}
		}

		// Detect if(...) {
		if s.ifStartRe.MatchString(trimmed) {
			cond := extractCondition(trimmed)
			stack = append(stack, frame{
				condition: cond,
				depth:     depth,
				lineNum:   i + 1,
			})
			continue
		}

		// Detect } else {
		if s.elseRe.MatchString(trimmed) && len(stack) > 0 {
			// The top frame is now negated
			top := &stack[len(stack)-1]
			top.isNegated = !top.isNegated
		}
	}

	if len(stack) == 0 {
		return &BranchContext{Depth: depth}
	}

	var conditions []ConditionFrame
	for _, f := range stack {
		conditions = append(conditions, ConditionFrame{
			Condition: f.condition,
			IsNegated: f.isNegated,
			LineNum:   f.lineNum,
		})
	}

	return &BranchContext{
		Conditions: conditions,
		Depth:      depth,
	}
}

// isMsgSenderCondition returns true if the condition involves msg.sender.
func isMsgSenderCondition(condition string) bool {
	return regexp.MustCompile(
		`msg\.sender\s*==|msg\.sender\s*!=|` +
			`\w+\s*\[\s*msg\.sender\s*\]|` +
			`hasRole\s*\(.*msg\.sender|` +
			`_checkRole\s*\(`,
	).MatchString(condition)
}

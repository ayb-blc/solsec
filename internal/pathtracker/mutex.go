// internal/pathtracker/mutex.go

package pathtracker

import (
	"regexp"
	"strings"
)

type mutexScanner struct {
	// require(!_locked) or require(_status == NOT_ENTERED)
	lockCheckRe *regexp.Regexp

	// _locked = true or _status = ENTERED
	lockSetRe *regexp.Regexp

	// _locked = false or _status = NOT_ENTERED
	lockResetRe *regexp.Regexp

	// State variable declaration pattern (to confirm lockVar is a state var)
	stateVarRe *regexp.Regexp
}

func newMutexScanner() *mutexScanner {
	return &mutexScanner{
		lockCheckRe: regexp.MustCompile(
			`require\s*\(\s*!\s*(_?\w*(?:locked|entered|mutex|reentrancy)\w*)\s*[,)]|` +
				`if\s*\(\s*(_?\w*(?:locked|entered|mutex)\w*)\s*\)\s*revert`,
		),
		lockSetRe: regexp.MustCompile(
			`(_?\w*(?:locked|entered|mutex|reentrancy)\w*)\s*=\s*true\b`,
		),
		lockResetRe: regexp.MustCompile(
			`(_?\w*(?:locked|entered|mutex|reentrancy)\w*)\s*=\s*false\b`,
		),
		stateVarRe: regexp.MustCompile(
			`^\s*bool\s+(?:private\s+|internal\s+|public\s+)?(_?\w+)\s*(?:=\s*false\s*)?;`,
		),
	}
}

// find searches bodyLines for a complete mutex pattern:
// check → set → reset. Returns nil if not found.
func (s *mutexScanner) find(bodyLines []string, contractSrc string) *MutexPattern {
	var checkLine, setLine, resetLine int
	var lockVar string

	for i, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		lineNum := i + 1

		// Step 1: find the check (require(!locked))
		if lockVar == "" {
			if m := s.lockCheckRe.FindStringSubmatch(trimmed); m != nil {
				// Extract variable name from capture groups
				for _, cap := range m[1:] {
					if cap != "" {
						lockVar = cap
						checkLine = lineNum
						break
					}
				}
			}
			continue
		}

		// Step 2: find the set (locked = true) for the same variable
		if setLine == 0 {
			if m := s.lockSetRe.FindStringSubmatch(trimmed); m != nil {
				if len(m) > 1 && m[1] == lockVar {
					setLine = lineNum
				}
			}
			continue
		}

		// Step 3: find the reset (locked = false) for the same variable
		if m := s.lockResetRe.FindStringSubmatch(trimmed); m != nil {
			if len(m) > 1 && m[1] == lockVar {
				resetLine = lineNum
				break
			}
		}
	}

	// All three steps found?
	if lockVar == "" || setLine == 0 || resetLine == 0 {
		return nil
	}

	// Verify lockVar is a state variable (not a local)
	// by checking if it appears as a bool declaration in contract source
	if !s.isStateVar(lockVar, contractSrc) {
		return nil
	}

	return &MutexPattern{
		LockVar:   lockVar,
		CheckLine: checkLine,
		SetLine:   setLine,
		ResetLine: resetLine,
	}
}

func (s *mutexScanner) isStateVar(varName, src string) bool {
	depth := 0
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if depth <= 1 && s.stateVarRe.MatchString(trimmed) {
			m := s.stateVarRe.FindStringSubmatch(trimmed)
			if len(m) > 1 && m[1] == varName {
				return true
			}
		}

		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					depth = 0
				}
			}
		}
	}
	return false
}

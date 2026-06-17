package detectors

import (
	"regexp"
	"strings"
)

type sourceScope struct {
	kind      string
	name      string
	startLine int
	endLine   int
}

var sourceScopeStartRe = regexp.MustCompile(`^\s*(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_]\w*)`)

func sourceScopeAtLine(lines []string, lineNum int) (sourceScope, bool) {
	for _, scope := range sourceScopes(lines) {
		if lineNum >= scope.startLine && lineNum <= scope.endLine {
			return scope, true
		}
	}
	return sourceScope{}, false
}

func isLineInScopeKind(lines []string, lineNum int, kinds ...string) bool {
	scope, ok := sourceScopeAtLine(lines, lineNum)
	if !ok {
		return false
	}
	for _, kind := range kinds {
		if scope.kind == kind {
			return true
		}
	}
	return false
}

func sourceScopes(lines []string) []sourceScope {
	var scopes []sourceScope
	var current *sourceScope
	depth := 0
	sawOpen := false

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			m := sourceScopeStartRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			current = &sourceScope{
				kind:      strings.ToLower(m[1]),
				name:      m[2],
				startLine: lineNum,
			}
			depth = 0
			sawOpen = false
		}

		for _, ch := range line {
			switch ch {
			case '{':
				depth++
				sawOpen = true
			case '}':
				depth--
			}
		}

		if sawOpen && depth <= 0 {
			current.endLine = lineNum
			scopes = append(scopes, *current)
			current = nil
		}
	}

	if current != nil {
		current.endLine = len(lines)
		scopes = append(scopes, *current)
	}

	return scopes
}

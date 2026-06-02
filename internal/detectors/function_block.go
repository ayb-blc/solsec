package detectors

import (
	"regexp"
	"strings"
)

type fnBlock struct {
	name       string
	signature  string // "function withdraw() external payable"
	lines      []string
	startLine  int
	visibility string   // public, external, internal, private
	modifiers  []string // nonReentrant, onlyOwner, vb.
	mutability string   // pure, view, payable, nonpayable
}

var (
	fnStartRe     = regexp.MustCompile(`^\s*(?:function\s+(\w+)|def\s+(\w+))\s*\(`)
	visibilityRe2 = regexp.MustCompile(`\b(public|external|internal|private)\b`)
	mutabilityRe  = regexp.MustCompile(`\b(pure|view|payable)\b`)
)

func extractFunctions(lines []string) []*fnBlock {
	var blocks []*fnBlock
	var current *fnBlock
	depth := 0

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			m := fnStartRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := m[1]
			if name == "" {
				name = m[2] // Vyper def
			}
			current = &fnBlock{
				name:      name,
				signature: strings.TrimSpace(line),
				startLine: lineNum,
			}
			current.visibility = extractVisibility(line)
			current.mutability = extractMutability(line)
			current.modifiers = extractModifiers(line)
			depth = 0
		}

		current.lines = append(current.lines, line)

		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}

		if depth == 0 && len(current.lines) > 1 {
			mods := extractModifiers(line)
			current.modifiers = appendUnique(current.modifiers, mods...)
		}

		if depth == 0 && len(current.lines) > 0 {
			if containsBrace(current.lines) {
				blocks = append(blocks, current)
				current = nil
			}
		}
	}

	return blocks
}

func (fn *fnBlock) isPureOrView() bool {
	return fn.mutability == "pure" || fn.mutability == "view"
}

func (fn *fnBlock) hasModifier(name string) bool {
	for _, m := range fn.modifiers {
		if m == name {
			return true
		}
	}
	return false
}

func extractVisibility(sig string) string {
	m := visibilityRe2.FindString(sig)
	return m
}

func extractMutability(sig string) string {
	m := mutabilityRe.FindString(sig)
	return m
}

func extractModifiers(sig string) []string {
	knownKeywords := map[string]bool{
		"function": true, "returns": true, "public": true, "external": true,
		"internal": true, "private": true, "pure": true, "view": true,
		"payable": true, "virtual": true, "override": true, "memory": true,
		"storage": true, "calldata": true, "indexed": true,
	}

	clean := regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(sig, "()")
	words := regexp.MustCompile(`\b[a-zA-Z_]\w*\b`).FindAllString(clean, -1)

	var mods []string
	for _, w := range words {
		if !knownKeywords[w] && !strings.HasPrefix(w, "uint") &&
			!strings.HasPrefix(w, "int") && !strings.HasPrefix(w, "bytes") &&
			w != "string" && w != "bool" && w != "address" {
			mods = append(mods, w)
		}
	}
	return mods
}

func containsBrace(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "{") {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, items ...string) []string {
	existing := make(map[string]bool, len(slice))
	for _, s := range slice {
		existing[s] = true
	}
	for _, item := range items {
		if !existing[item] {
			slice = append(slice, item)
			existing[item] = true
		}
	}
	return slice
}

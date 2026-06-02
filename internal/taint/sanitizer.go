package taint

import (
	"regexp"
)

// SanitizerDB bilinen sanitizer pattern'lerini tutar.
//
// Sanitizer nedir?
type SanitizerDB struct {
	// Bilinen sanitizer pattern'leri
	patterns []sanitizerPattern
}

type sanitizerPattern struct {
	regex       *regexp.Regexp
	description string
	strong      bool
}

// Confidence is local to taint post-processing to avoid importing analyzer and
// creating an analyzer -> taint -> analyzer cycle.
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

func NewSanitizerDB() *SanitizerDB {
	return &SanitizerDB{
		patterns: []sanitizerPattern{
			{
				regex:       regexp.MustCompile(`require\s*\(\s*(\w+)\s*<=\s*`),
				description: "Upper bound check via require",
				strong:      true,
			},
			{
				regex:       regexp.MustCompile(`require\s*\(\s*(\w+)\s*>\s*0`),
				description: "Non-zero check",
				strong:      false,
			},
			{
				regex:       regexp.MustCompile(`if\s*\(\s*(\w+)\s*>\s*\w+\s*\)\s*(revert|return)`),
				description: "Conditional revert on overflow",
				strong:      true,
			},
			{
				regex:       regexp.MustCompile(`\.add\s*\(|\.sub\s*\(|\.mul\s*\(`),
				description: "SafeMath operation",
				strong:      true,
			},
			{
				regex: regexp.MustCompile(
					`require\s*\(\s*msg\.sender\s*==\s*(owner|admin)`,
				),
				description: "Ownership check",
				strong:      true,
			},
		},
	}
}

func (db *SanitizerDB) SanitizedVars(lines []string, startLine, endLine int) map[string]bool {
	sanitized := make(map[string]bool)

	for i := startLine; i < endLine && i < len(lines); i++ {
		line := lines[i]

		for _, p := range db.patterns {
			matches := p.regex.FindStringSubmatch(line)
			if len(matches) >= 2 && p.strong {
				sanitized[matches[1]] = true
			}
		}
	}

	return sanitized
}

func (db *SanitizerDB) IsSanitizedBefore(varName string, line int, allLines []string) bool {
	sanitized := db.SanitizedVars(allLines, 0, line)
	return sanitized[varName]
}

func (db *SanitizerDB) ConfidenceAdjustment(
	varName string,
	sinkLine int,
	allLines []string,
	originalConfidence Confidence,
) Confidence {
	if db.IsSanitizedBefore(varName, sinkLine, allLines) {
		if originalConfidence > ConfidenceLow {
			return originalConfidence - 1
		}
	}
	return originalConfidence
}

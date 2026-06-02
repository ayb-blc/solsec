package detectors

import (
	"regexp"
	"strings"
)

type functionBlock struct {
	name         string
	contractName string
	signature    string // "function withdraw() external payable"
	visibility   string // public, external, internal, private
	lines        []string
	startLine    int // 1-indexed
}

var (
	funcPattern = regexp.MustCompile(
		`^\s*function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?`,
	)
	contractPattern = regexp.MustCompile(`^\s*contract\s+(\w+)`)
	visibilityRe    = regexp.MustCompile(`\b(public|external|internal|private)\b`)
)

func extractFunctionBlocks(lines []string) []functionBlock {
	var blocks []functionBlock
	var current *functionBlock
	depth := 0
	currentContract := ""

	for i, line := range lines {
		lineNum := i + 1

		if m := contractPattern.FindStringSubmatch(line); m != nil {
			currentContract = m[1]
		}

		if current == nil {
			if m := funcPattern.FindStringSubmatch(line); m != nil {
				vis := ""
				if vm := visibilityRe.FindString(line); vm != "" {
					vis = vm
				}
				current = &functionBlock{
					name:         m[1],
					contractName: currentContract,
					signature:    strings.TrimSpace(line),
					visibility:   vis,
					startLine:    lineNum,
				}
				depth = 0
			}
		}

		if current != nil {
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
				blocks = append(blocks, *current)
				current = nil
			}
		}
	}
	return blocks
}

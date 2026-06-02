package suppression

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/rules"
)

// Desteklenen formatlar:
//
//	// solsec-disable-next-line SOLSEC-REENTRANCY-001
//	// solsec-disable-next-line SOLSEC-REENTRANCY-001, SOLSEC-AUTH-001
//	// solsec-disable-next-line all
//	/* solsec-disable-next-line SOLSEC-REENTRANCY-001 */
//
//	// solsec-enable SOLSEC-REENTRANCY-001    (yeniden aktif et)
//
//
//	# solsec-disable-next-line SOLSEC-REENTRANCY-001
type InlineSuppressionParser struct {
	// nextLinePattern "solsec-disable-next-line <ID,...>"
	nextLinePattern *regexp.Regexp

	// disablePattern  "solsec-disable <ID,...>"
	disablePattern *regexp.Regexp

	// enablePattern "solsec-enable <ID,...>"
	enablePattern *regexp.Regexp
}

type InlineSuppression struct {
	Line int

	Kind SuppressionKind

	// RuleIDs susturulacak rule ID'leri
	RuleIDs []rules.RuleID

	AppliesTo int
}

type SuppressionKind int

const (
	KindNextLine SuppressionKind = iota // solsec-disable-next-line
	KindDisable
	KindEnable // solsec-enable (block sonu)
)

type FileSuppressions struct {
	NextLine map[int]map[rules.RuleID]bool

	DisabledRanges map[rules.RuleID][]lineRange

	GlobalDisable map[rules.RuleID]bool
}

type lineRange struct {
	Start int
	End   int
}

func NewInlineSuppressionParser() *InlineSuppressionParser {
	return &InlineSuppressionParser{
		// // solsec-disable-next-line SOLSEC-REENTRANCY-001, SOLSEC-AUTH-001
		// # solsec-disable-next-line SOLSEC-REENTRANCY-001
		nextLinePattern: regexp.MustCompile(
			`(?://|#|/\*)\s*solsec-disable-next-line\s+([A-Za-z0-9,\s_-]+?)(?:\s*\*/)?$`,
		),

		// // solsec-disable SOLSEC-REENTRANCY-001
		disablePattern: regexp.MustCompile(
			`(?://|#|/\*)\s*solsec-disable\s*(.*?)(?:\s*\*/)?$`,
		),

		// // solsec-enable SOLSEC-REENTRANCY-001
		enablePattern: regexp.MustCompile(
			`(?://|#|/\*)\s*solsec-enable\s*(.*?)(?:\s*\*/)?$`,
		),
	}
}

func (p *InlineSuppressionParser) Parse(source string) *FileSuppressions {
	fs := &FileSuppressions{
		NextLine:       make(map[int]map[rules.RuleID]bool),
		DisabledRanges: make(map[rules.RuleID][]lineRange),
		GlobalDisable:  make(map[rules.RuleID]bool),
	}

	openBlocks := make(map[rules.RuleID]int)

	scanner := bufio.NewScanner(strings.NewReader(source))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// NextLine direktifi
		if m := p.nextLinePattern.FindStringSubmatch(line); m != nil {
			ids := parseRuleIDs(m[1])
			if _, ok := fs.NextLine[lineNum+1]; !ok {
				fs.NextLine[lineNum+1] = make(map[rules.RuleID]bool)
			}
			for _, id := range ids {
				fs.NextLine[lineNum+1][id] = true
			}
			continue
		}

		if m := p.disablePattern.FindStringSubmatch(line); m != nil {
			ids := parseRuleIDs(m[1])
			if len(ids) == 0 {
				ids = []rules.RuleID{"*"}
			}
			for _, id := range ids {
				openBlocks[id] = lineNum
			}
			continue
		}

		// Enable (block sonu)
		if m := p.enablePattern.FindStringSubmatch(line); m != nil {
			ids := parseRuleIDs(m[1])
			if len(ids) == 0 {
				ids = []rules.RuleID{"*"}
			}
			for _, id := range ids {
				if start, ok := openBlocks[id]; ok {
					fs.DisabledRanges[id] = append(
						fs.DisabledRanges[id],
						lineRange{Start: start, End: lineNum},
					)
					delete(openBlocks, id)
				}
			}
			continue
		}
	}

	for id, start := range openBlocks {
		fs.DisabledRanges[id] = append(
			fs.DisabledRanges[id],
			lineRange{Start: start, End: -1},
		)
	}

	return fs
}

func (fs *FileSuppressions) IsSuppressed(ruleID rules.RuleID, line int) bool {
	if ruleSet, ok := fs.NextLine[line]; ok {
		if ruleSet["*"] || ruleSet[ruleID] {
			return true
		}
	}

	for _, id := range []rules.RuleID{ruleID, "*"} {
		if ranges, ok := fs.DisabledRanges[id]; ok {
			for _, r := range ranges {
				if line >= r.Start {
					if r.End == -1 || line <= r.End {
						return true
					}
				}
			}
		}
	}

	return false
}

func parseRuleIDs(s string) []rules.RuleID {
	s = strings.TrimSpace(s)
	if s == "" || strings.ToLower(s) == "all" {
		return []rules.RuleID{"*"}
	}

	parts := strings.Split(s, ",")
	var ids []rules.RuleID
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.ToLower(part) == "all" {
			return []rules.RuleID{"*"}
		}
		ids = append(ids, rules.RuleID(part))
	}
	return ids
}

func FormatDirective(ruleID rules.RuleID, lang string) string {
	prefix := "//"
	if lang == "vyper" {
		prefix = "#"
	}
	return fmt.Sprintf("%s solsec-disable-next-line %s", prefix, ruleID)
}

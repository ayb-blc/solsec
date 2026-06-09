// internal/inheritancegraph/parser.go

package inheritancegraph

import (
	"regexp"
	"strings"
)

// fileParser extracts contract and function declarations from a single
// Solidity source file using regex-based analysis.
// It is intentionally lightweight and does not require compilation.
type fileParser struct {
	contractDeclRe *regexp.Regexp

	funcStartRe *regexp.Regexp

	modifierStartRe *regexp.Regexp

	importRe *regexp.Regexp

	stateVarRe *regexp.Regexp

	mappingStateVarRe *regexp.Regexp
}

func newFileParser() *fileParser {
	return &fileParser{
		// Matches: contract Foo is Bar, Baz {
		//          abstract contract Foo is Bar {
		//          interface IFoo is IBar {
		//          library SafeMath {
		contractDeclRe: regexp.MustCompile(
			`(?:^|;)\s*(abstract\s+)?` +
				`(contract|interface|library)\s+(\w+)` +
				`(?:\s+is\s+([^{};]+))?` +
				`\s*\{?`,
		),

		// Matches function declarations (first line only)
		funcStartRe: regexp.MustCompile(
			`^\s*function\s+(\w+)\s*\(`,
		),

		modifierStartRe: regexp.MustCompile(
			`^\s*modifier\s+(\w+)\s*\(`,
		),

		// Matches import statements
		importRe: regexp.MustCompile(
			`^\s*import\s+` +
				`(?:` +
				`"([^"]+)"` + `|` + // import "path"
				`'([^']+)'` + `|` + // import 'path'
				`\{[^}]+\}\s+from\s+"([^"]+)"` + `|` + // import { X } from "path"
				`\{[^}]+\}\s+from\s+'([^']+)'` + // import { X } from 'path'
				`)`,
		),

		stateVarRe: regexp.MustCompile(
			`^\s*(uint\d*|int\d*|address|bool|bytes\d*|string|mapping|` +
				`[A-Z]\w+(?:\[\])?)` +
				`\s+(?:public|private|internal|)?\s*` +
				`(?:constant\s+|immutable\s+)?` +
				`(\w+)\s*(?:=|;)`,
		),

		mappingStateVarRe: regexp.MustCompile(
			`^\s*mapping\s*\([^)]+\)\s+` +
				`(?:(public|private|internal)\s+)?` +
				`(?:constant\s+|immutable\s+)?` +
				`(\w+)\s*(?:=|;)`,
		),
	}
}

// parseResult holds everything extracted from a single source file.
type parseResult struct {
	filepath  string
	contracts []*contractDecl
	imports   []string
}

// contractDecl is an intermediate type before graph nodes are linked.
type contractDecl struct {
	name        string
	kind        ContractKind
	parentNames []string // unresolved parent names from "is" clause
	functions   []*funcDecl
	modifiers   map[string]*ModifierDef
	stateVars   []StateVar
	startLine   int
	sourceLines []string
}

type modifierInProgress struct {
	name      string
	params    string
	lineNum   int
	bodyLines []string
}

type funcDecl struct {
	name       string
	signature  string
	params     string
	modifiers  []string
	visibility string
	mutability string
	returns    string
	isVirtual  bool
	isOverride bool
	lineNumber int
	bodyLines  []string
}

// parse extracts all contracts and imports from a Solidity source file.
func (p *fileParser) parse(filepath string, lines []string) *parseResult {
	result := &parseResult{filepath: filepath}

	var currentContract *contractDecl
	contractDepth := 0 // brace depth within current contract
	functionDepth := 0 // brace depth within current function
	var currentFunc *funcDecl
	inFunction := false
	var currentModifier *modifierInProgress
	modifierDepth := 0
	inModifier := false

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Count braces for scope tracking
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")

		// --- Import parsing ---
		if currentContract == nil {
			if m := p.importRe.FindStringSubmatch(line); m != nil {
				for _, capture := range m[1:] {
					if capture != "" {
						result.imports = append(result.imports, capture)
						break
					}
				}
			}
		}

		// --- Contract declaration ---
		if currentContract == nil {
			if m := p.contractDeclRe.FindStringSubmatch(line); m != nil {
				decl := &contractDecl{
					name:      m[3],
					kind:      parseContractKind(m[1], m[2]),
					modifiers: make(map[string]*ModifierDef),
					startLine: lineNum,
				}
				// Parse parent list from "is" clause
				if m[4] != "" {
					decl.parentNames = parseParentNames(m[4])
				}
				currentContract = decl
				contractDepth = 0
				result.contracts = append(result.contracts, decl)
				// Don't count the opening brace on this line yet
				// (the { may be on the same line)
				if strings.Contains(line, "{") {
					contractDepth++
				}
				continue
			}
		}

		if currentContract == nil {
			continue
		}

		// Accumulate contract source lines
		currentContract.sourceLines = append(currentContract.sourceLines, line)

		// --- Function parsing (within contract) ---
		if !inFunction && !inModifier {
			if m := p.funcStartRe.FindStringSubmatch(line); m != nil && contractDepth == 1 {
				sig := p.collectSignature(lines, i)
				fd := p.parseFunction(m[1], sig, lineNum)
				currentFunc = fd
				inFunction = true
				currentFunc.bodyLines = append(currentFunc.bodyLines, line)
				functionDepth = openBraces - closeBraces
				if functionDepth <= 0 && strings.Contains(line, "{") {
					currentContract.functions = append(currentContract.functions, currentFunc)
					currentFunc = nil
					inFunction = false
				}
				contractDepth += openBraces - closeBraces
				continue
			}
		}

		// --- Modifier parsing (within contract) ---
		if !inFunction && !inModifier {
			if m := p.modifierStartRe.FindStringSubmatch(line); m != nil && contractDepth == 1 {
				currentModifier = &modifierInProgress{
					name:      m[1],
					params:    extractParamString(line),
					lineNum:   lineNum,
					bodyLines: []string{line},
				}
				inModifier = true
				modifierDepth = openBraces - closeBraces
				if modifierDepth <= 0 && strings.Contains(line, "{") {
					p.finalizeModifier(currentContract, currentModifier)
					currentModifier = nil
					inModifier = false
				}
				contractDepth += openBraces - closeBraces
				continue
			}
		}

		if inFunction {
			currentFunc.bodyLines = append(currentFunc.bodyLines, line)
			functionDepth += openBraces - closeBraces
			if functionDepth <= 0 {
				currentContract.functions = append(currentContract.functions, currentFunc)
				currentFunc = nil
				inFunction = false
			}
			// Don't double-count these braces for contract depth
			contractDepth += openBraces - closeBraces
			continue
		}

		if inModifier {
			currentModifier.bodyLines = append(currentModifier.bodyLines, line)
			modifierDepth += openBraces - closeBraces
			if modifierDepth <= 0 {
				p.finalizeModifier(currentContract, currentModifier)
				currentModifier = nil
				inModifier = false
			}
			contractDepth += openBraces - closeBraces
			continue
		}

		// --- State variable (contract scope, not inside function) ---
		if contractDepth == 1 {
			if sv, ok := p.parseStateVar(line, lineNum); ok {
				currentContract.stateVars = append(currentContract.stateVars, sv)
			}
		}

		// Update contract brace depth
		contractDepth += openBraces - closeBraces
		if contractDepth <= 0 {
			// Contract block ended
			currentContract = nil
			contractDepth = 0
		}
	}

	return result
}

// collectSignature gathers a potentially multi-line function signature
// up to and including the opening brace.
func (p *fileParser) collectSignature(lines []string, startIdx int) string {
	var parts []string
	for i := startIdx; i < len(lines) && i < startIdx+12; i++ {
		parts = append(parts, strings.TrimSpace(lines[i]))
		if strings.Contains(lines[i], "{") {
			break
		}
	}
	return strings.Join(parts, " ")
}

// parseFunction extracts structured information from a function signature string.
func (p *fileParser) parseFunction(name, sig string, lineNum int) *funcDecl {
	fd := &funcDecl{
		name:       name,
		signature:  sig,
		lineNumber: lineNum,
	}

	// Extract parameters
	fd.params = extractParamString(sig)

	// Extract everything after params
	afterParams := afterParamList(sig)

	// Visibility
	for _, vis := range []string{"external", "public", "internal", "private"} {
		if matchWord(afterParams, vis) {
			fd.visibility = vis
			break
		}
	}

	// Mutability
	for _, mut := range []string{"view", "pure", "payable"} {
		if matchWord(afterParams, mut) {
			fd.mutability = mut
			break
		}
	}

	fd.isVirtual = matchWord(afterParams, "virtual")
	fd.isOverride = matchWord(afterParams, "override")

	// Modifiers: words that remain after removing known keywords
	fd.modifiers = extractModifiers(afterParams)

	return fd
}

func (p *fileParser) finalizeModifier(contract *contractDecl, mod *modifierInProgress) {
	if contract == nil || mod == nil {
		return
	}
	classifier := newBodyClassifier()
	category, checks := classifier.classify(mod.bodyLines)
	contract.modifiers[mod.name] = &ModifierDef{
		Name:        mod.name,
		Params:      mod.params,
		BodyLines:   append([]string(nil), mod.bodyLines...),
		Category:    category,
		Checks:      checks,
		IsWellKnown: false,
	}
}

func (p *fileParser) parseStateVar(line string, lineNum int) (StateVar, bool) {
	if m := p.mappingStateVarRe.FindStringSubmatch(line); m != nil {
		return StateVar{
			TypeName:    "mapping",
			Name:        m[2],
			Visibility:  m[1],
			LineNumber:  lineNum,
			IsConstant:  strings.Contains(line, "constant"),
			IsImmutable: strings.Contains(line, "immutable"),
		}, true
	}

	m := p.stateVarRe.FindStringSubmatch(line)
	if m == nil {
		return StateVar{}, false
	}
	sv := StateVar{
		TypeName:    strings.TrimSpace(m[1]),
		Name:        m[2],
		LineNumber:  lineNum,
		IsConstant:  strings.Contains(line, "constant"),
		IsImmutable: strings.Contains(line, "immutable"),
	}
	for _, vis := range []string{"public", "private", "internal"} {
		if strings.Contains(line, vis) {
			sv.Visibility = vis
			break
		}
	}
	return sv, true
}

// --- helpers ---

func parseContractKind(abstractKw, keyword string) ContractKind {
	if abstractKw != "" || strings.Contains(abstractKw, "abstract") {
		return KindAbstract
	}
	switch keyword {
	case "interface":
		return KindInterface
	case "library":
		return KindLibrary
	default:
		return KindContract
	}
}

func parseParentNames(isClause string) []string {
	raw := strings.Split(isClause, ",")
	var out []string
	for _, r := range raw {
		// Remove constructor arguments: Ownable(msg.sender) becomes Ownable.
		name := strings.TrimSpace(r)
		if idx := strings.Index(name, "("); idx > 0 {
			name = name[:idx]
		}
		name = strings.TrimSpace(name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func extractParamString(sig string) string {
	start := strings.Index(sig, "(")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(sig); i++ {
		switch sig[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sig[start+1 : i]
			}
		}
	}
	return ""
}

func afterParamList(sig string) string {
	depth := 0
	started := false
	for i, ch := range sig {
		switch ch {
		case '(':
			depth++
			started = true
		case ')':
			depth--
			if started && depth == 0 {
				return sig[i+1:]
			}
		}
	}
	return ""
}

var knownKeywords = map[string]bool{
	"external": true, "public": true, "internal": true, "private": true,
	"view": true, "pure": true, "payable": true,
	"virtual": true, "override": true,
	"returns": true, "memory": true, "storage": true, "calldata": true,
}

func extractModifiers(afterParams string) []string {
	returnsRe := regexp.MustCompile(`returns\s*\([^)]*\)`)
	cleaned := returnsRe.ReplaceAllString(afterParams, "")
	wordRe := regexp.MustCompile(`\b[a-zA-Z_]\w*\b`)
	words := wordRe.FindAllString(cleaned, -1)
	var mods []string
	for _, w := range words {
		if !knownKeywords[w] && !isTypeKeyword(w) {
			mods = append(mods, w)
		}
	}
	return mods
}

func isTypeKeyword(w string) bool {
	return strings.HasPrefix(w, "uint") ||
		strings.HasPrefix(w, "int") ||
		strings.HasPrefix(w, "bytes") ||
		w == "string" || w == "bool" || w == "address"
}

func matchWord(s, word string) bool {
	return regexp.MustCompile(`\b` + word + `\b`).MatchString(s)
}

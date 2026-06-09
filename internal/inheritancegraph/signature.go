// internal/inheritancegraph/signature.go

package inheritancegraph

import (
	"regexp"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ParsedSignature holds the canonical, structured form of a Solidity
// function signature. Used for override matching and selector computation.
type ParsedSignature struct {
	// Name is the function name.
	Name string

	// Params holds the normalized parameter types in declaration order.
	// Names are stripped; only types remain.
	Params []ParamType

	// Returns holds the normalized return types.
	Returns []ParamType

	// Canonical is the ABI-canonical signature string:
	// "name(type1,type2)" with no spaces, normalized types, and no return types.
	Canonical string

	// Selector is the 4-byte ABI selector: keccak256(Canonical)[0:4].
	Selector [4]byte
}

// ParamType represents a single normalized parameter type.
type ParamType struct {
	// Base type after normalization, e.g. "uint256", "address", "bytes32".
	Base string

	// For array types: "uint256[]", "bytes32[3]"
	ArraySuffix string // e.g. "[]", "[3]", "[][]"

	// For tuple types: "(uint256,address)"
	TupleFields []ParamType

	IsTuple bool
}

// String returns the canonical string for this type.
func (p ParamType) String() string {
	if p.IsTuple {
		fields := make([]string, len(p.TupleFields))
		for i, f := range p.TupleFields {
			fields[i] = f.String()
		}
		return "(" + strings.Join(fields, ",") + ")" + p.ArraySuffix
	}
	return p.Base + p.ArraySuffix
}

// SignatureResolver parses and normalizes Solidity function signatures.
// It is stateless; all methods are pure functions over strings.
type SignatureResolver struct{}

// NewSignatureResolver returns a SignatureResolver.
func NewSignatureResolver() *SignatureResolver { return &SignatureResolver{} }

// Parse extracts a ParsedSignature from a raw function declaration line.
// The input may be a full declaration:
//
//	"function setFee(uint fee_) external onlyOwner { ... }"
//
// or just a signature fragment:
//
//	"setFee(uint256)"
func (r *SignatureResolver) Parse(raw string) *ParsedSignature {
	// Extract function name
	name := extractFuncName(raw)
	if name == "" {
		return nil
	}

	rawParams := extractBetweenParens(raw)

	params := r.parseParamList(rawParams)

	canonical := buildCanonical(name, params)

	selector := computeSelector(canonical)

	// Parse return types if present
	var returns []ParamType
	if idx := strings.Index(raw, "returns"); idx > 0 {
		after := raw[idx+len("returns"):]
		rawReturns := extractBetweenParens(after)
		returns = r.parseParamList(rawReturns)
	}

	return &ParsedSignature{
		Name:      name,
		Params:    params,
		Returns:   returns,
		Canonical: canonical,
		Selector:  selector,
	}
}

// CanonicalOf returns the canonical signature string for a function
// given its name and a raw parameter list string.
//
//	CanonicalOf("transfer", "address to, uint256 amount") → "transfer(address,uint256)"
func (r *SignatureResolver) CanonicalOf(name string, rawParams string) string {
	params := r.parseParamList(rawParams)
	return buildCanonical(name, params)
}

// SelectorsMatch reports whether two raw function signatures resolve to
// the same ABI selector (i.e., same name and same parameter types after
// normalization).
func (r *SignatureResolver) SelectorsMatch(rawA, rawB string) bool {
	a := r.Parse(rawA)
	b := r.Parse(rawB)
	if a == nil || b == nil {
		return false
	}
	return a.Selector == b.Selector
}

// NormalizeType converts a raw Solidity type to its canonical ABI form.
//
//	uint            -> uint256
//	int             -> int256
//	byte            -> bytes1
//	uint[]          -> uint256[]
//	(uint, address) -> (uint256,address)   [tuple]
func (r *SignatureResolver) NormalizeType(t string) string {
	pt := r.parseType(strings.TrimSpace(t))
	return pt.String()
}

// Internal parsing.

// parseParamList splits a raw parameter list and normalizes each type.
// Input:  "address to, uint256 amount, bytes calldata data"
// Output: [{Base:"address"}, {Base:"uint256"}, {Base:"bytes"}]
func (r *SignatureResolver) parseParamList(raw string) []ParamType {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// Split on commas that are not inside parentheses
	parts := splitTopLevel(raw, ',')
	var out []ParamType
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		typePart := extractTypeFromParam(part)
		out = append(out, r.parseType(typePart))
	}
	return out
}

// parseType parses and normalizes a single Solidity type string.
func (r *SignatureResolver) parseType(t string) ParamType {
	t = strings.TrimSpace(t)

	// Strip storage location keywords
	for _, loc := range []string{"calldata", "memory", "storage"} {
		t = strings.TrimSuffix(t, " "+loc)
		t = strings.TrimSuffix(t, "\t"+loc)
		t = strings.ReplaceAll(t, " "+loc+" ", " ")
	}
	t = strings.TrimSpace(t)

	if strings.HasPrefix(t, "(") {
		inner, suffix := extractTuple(t)
		fields := r.parseParamList(inner)
		return ParamType{
			IsTuple:     true,
			TupleFields: fields,
			ArraySuffix: normalizeArraySuffix(suffix),
		}
	}

	// Array suffix: uint256[], bytes32[3], address[][]
	base, arraySuffix := splitArraySuffix(t)

	return ParamType{
		Base:        normalizeBaseType(base),
		ArraySuffix: normalizeArraySuffix(arraySuffix),
	}
}

// Type normalization rules.

// normalizeBaseType converts Solidity type aliases to canonical ABI types.
func normalizeBaseType(t string) string {
	t = strings.TrimSpace(t)

	// "address payable" becomes "address".
	t = strings.TrimSuffix(t, " payable")
	t = strings.ReplaceAll(t, " payable", "")

	switch t {
	case "uint":
		return "uint256"
	case "int":
		return "int256"
	case "byte":
		return "bytes1"
	case "":
		return ""
	}

	// Sized aliases are already canonical: uint128, bytes32, etc.
	return t
}

func normalizeArraySuffix(s string) string {
	// Remove spaces inside brackets: "[ 3 ]" becomes "[3]".
	spaceRe := regexp.MustCompile(`\[\s*(\d*)\s*\]`)
	return spaceRe.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.TrimSpace(m[1 : len(m)-1])
		return "[" + inner + "]"
	})
}

// Helpers.

func extractFuncName(raw string) string {
	// Handle "function name(...)" or just "name(...)"
	funcRe := regexp.MustCompile(`\bfunction\s+(\w+)\s*\(`)
	if m := funcRe.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	// Bare "name(" form
	bareRe := regexp.MustCompile(`^(\w+)\s*\(`)
	if m := bareRe.FindStringSubmatch(strings.TrimSpace(raw)); m != nil {
		return m[1]
	}
	return ""
}

// extractBetweenParens returns the content between the first ( and its
// matching ), handling nested parentheses.
func extractBetweenParens(s string) string {
	start := strings.Index(s, "(")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[start+1 : i]
			}
		}
	}
	return ""
}

// extractTuple separates the inner fields of a tuple from any trailing
// array suffix. Input: "(uint256,address)[]" becomes ("uint256,address", "[]").
func extractTuple(t string) (inner, suffix string) {
	depth := 0
	for i, ch := range t {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return t[1:i], t[i+1:]
			}
		}
	}
	return t[1:], ""
}

// splitArraySuffix separates "uint256[3][]" into ("uint256", "[3][]").
func splitArraySuffix(t string) (base, suffix string) {
	idx := strings.Index(t, "[")
	if idx < 0 {
		return t, ""
	}
	return t[:idx], t[idx:]
}

// extractTypeFromParam extracts the type portion from a parameter declaration.
// "address to"        -> "address"
// "uint256 amount"    -> "uint256"
// "bytes calldata"    -> "bytes"      (storage location stripped)
// "uint256[] memory"  -> "uint256[]"
// "address"           -> "address"    (no name)
func extractTypeFromParam(param string) string {
	param = strings.TrimSpace(param)

	// Remove storage locations
	for _, loc := range []string{" calldata", " memory", " storage", " payable"} {
		if idx := strings.Index(param, loc); idx > 0 {
			param = strings.TrimSpace(param[:idx])
		}
	}

	// If there's a space after the type, everything before the last space
	// that isn't an array bracket is the type.
	// "address to" becomes "address".
	// "uint256[3] arr" becomes "uint256[3]".
	// "address" stays "address" (no name).
	if idx := strings.LastIndex(param, " "); idx > 0 {
		candidate := param[:idx]
		// Only strip if the remainder looks like a name (no type chars)
		rest := strings.TrimSpace(param[idx:])
		if isParamName(rest) {
			return candidate
		}
	}

	return param
}

// isParamName reports whether s looks like a parameter name (identifier)
// rather than a type keyword.
func isParamName(s string) bool {
	if s == "" {
		return false
	}
	// Parameter names are identifiers; type keywords contain digits or
	// special syntax like [], ()
	if strings.ContainsAny(s, "[]()") {
		return false
	}
	typeKeywords := map[string]bool{
		"uint256": true, "uint128": true, "uint64": true,
		"uint32": true, "uint16": true, "uint8": true,
		"int256": true, "int128": true, "int64": true,
		"address": true, "bool": true, "bytes": true,
		"bytes32": true, "bytes4": true, "bytes1": true,
		"string": true, "tuple": true,
	}
	return !typeKeywords[s]
}

// splitTopLevel splits s by sep, but ignores sep characters inside
// parentheses. Used for splitting "address,(uint256,bytes),bool" by ','.
func splitTopLevel(s string, sep rune) []string {
	var parts []string
	depth := 0
	start := 0
	for i, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case sep:
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// buildCanonical constructs the canonical signature string.
// "setFee" + [{uint256}] becomes "setFee(uint256)".
func buildCanonical(name string, params []ParamType) string {
	types := make([]string, len(params))
	for i, p := range params {
		types[i] = p.String()
	}
	return name + "(" + strings.Join(types, ",") + ")"
}

// computeSelector returns the 4-byte ABI selector for a canonical signature.
func computeSelector(canonical string) [4]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(canonical))
	sum := h.Sum(nil)
	var selector [4]byte
	copy(selector[:], sum[:4])
	return selector
}

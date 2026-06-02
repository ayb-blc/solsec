package parser

import (
	"fmt"
	"path/filepath"
	"strings"
)

type ParserRegistry struct {
	parsers []LanguageParser
}

func NewParserRegistry(parsers ...LanguageParser) *ParserRegistry {
	return &ParserRegistry{parsers: append([]LanguageParser(nil), parsers...)}
}

func DefaultRegistry() *ParserRegistry {
	return NewParserRegistry(
		NewSolidityParser(""),
		NewVyperParser(""),
	)
}

func DetectLanguage(path string) Language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sol":
		return LanguageSolidity
	case ".vy":
		return LanguageVyper
	default:
		return LanguageUnknown
	}
}

func (r *ParserRegistry) ParserFor(path string) (LanguageParser, error) {
	if r == nil {
		r = DefaultRegistry()
	}
	for _, p := range r.parsers {
		if p != nil && p.CanParse(path) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no parser registered for %q", path)
}

func (r *ParserRegistry) Parse(path string) (*UnifiedAST, error) {
	p, err := r.ParserFor(path)
	if err != nil {
		return nil, err
	}
	return p.Parse(path)
}

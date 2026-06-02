// Package fingerprint computes stable identities for findings so CI can
// distinguish new issues from already-known baseline findings.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type Fingerprint struct {
	ID         string
	Components Components
}

type Components struct {
	RuleID            string
	FilePath          string
	Contract          string
	Function          string
	NormalizedSnippet string
}

func Compute(f analyzer.Finding, projectRoot string) Fingerprint {
	components := Components{
		RuleID:            effectiveRuleID(f),
		FilePath:          normalizePath(f.Filepath, projectRoot),
		Contract:          normalizeToken(extractContract(f)),
		Function:          normalizeToken(extractFunction(f)),
		NormalizedSnippet: normalizeSnippet(f.CodeSnippet),
	}
	if components.NormalizedSnippet == "" {
		components.NormalizedSnippet = normalizeSnippet(f.Title)
	}

	h := sha256.New()
	_, _ = h.Write([]byte(strings.Join([]string{
		components.RuleID,
		components.FilePath,
		components.Contract,
		components.Function,
		components.NormalizedSnippet,
	}, "\x00")))

	sum := hex.EncodeToString(h.Sum(nil))
	prefix := "SOLSEC"
	if components.RuleID != "" {
		prefix = components.RuleID
	}
	return Fingerprint{
		ID:         prefix + "-" + sum[:12],
		Components: components,
	}
}

func ComputeAll(findings []analyzer.Finding, projectRoot string) {
	for i := range findings {
		findings[i].FingerprintID = Compute(findings[i], projectRoot).ID
	}
}

func effectiveRuleID(f analyzer.Finding) string {
	if f.RuleID != "" {
		return string(f.RuleID)
	}
	if f.DetectorName != "" {
		return f.DetectorName
	}
	return "unknown"
}

func normalizePath(path, projectRoot string) string {
	path = filepath.Clean(filepath.ToSlash(path))
	root := filepath.Clean(filepath.ToSlash(projectRoot))
	if root != "." && root != "" {
		if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
			path = rel
		}
	}
	path = filepath.ToSlash(path)
	path = strings.TrimPrefix(path, "./")
	return strings.ToLower(path)
}

func normalizeSnippet(snippet string) string {
	snippet = stripLineComment(snippet)
	snippet = strings.TrimSpace(snippet)
	fields := strings.Fields(snippet)
	return strings.Join(fields, " ")
}

func stripLineComment(s string) string {
	if idx := strings.Index(s, "//"); idx >= 0 {
		return s[:idx]
	}
	return s
}

func normalizeToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

var (
	contractPattern = regexp.MustCompile(`(?i)\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)`)
	functionPattern = regexp.MustCompile(`(?i)\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)`)
	quotedPattern   = regexp.MustCompile(`'([A-Za-z_][A-Za-z0-9_]*)'`)
)

func extractContract(f analyzer.Finding) string {
	m := contractPattern.FindStringSubmatch(f.Title + " " + f.Description)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractFunction(f analyzer.Finding) string {
	text := f.Title + " " + f.Description
	if m := functionPattern.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	if m := quotedPattern.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	return ""
}

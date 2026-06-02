package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/fingerprint"
)

// Baseline stores accepted findings so future scans can report only new issues.
type Baseline struct {
	Version string `json:"version"`

	CreatedAt time.Time `json:"created_at"`

	ProjectRoot string `json:"project_root"`

	ToolVersion string `json:"tool_version"`

	TotalFindings int `json:"total_findings"`

	Findings map[string]BaselineFinding `json:"findings"`
}

// BaselineFinding stores one finding inside a baseline file.
type BaselineFinding struct {
	// FingerprintID is the deterministic finding identifier.
	FingerprintID string `json:"fingerprint_id"`

	// RuleID is the detector rule identifier.
	RuleID string `json:"rule_id"`

	Severity string `json:"severity"`

	FilePath string `json:"file_path"`

	Title string `json:"title"`

	// SuppressedAt ne zaman baseline'a eklendi
	SuppressedAt time.Time `json:"suppressed_at"`

	Note string `json:"note,omitempty"`
}

func Create(
	results []analyzer.AnalysisResult,
	projectRoot string,
	toolVersion string,
) *Baseline {
	b := &Baseline{
		Version:     "1",
		CreatedAt:   time.Now().UTC(),
		ProjectRoot: projectRoot,
		ToolVersion: toolVersion,
		Findings:    make(map[string]BaselineFinding),
	}

	now := time.Now().UTC()
	for _, result := range results {
		for _, f := range result.Findings {
			fp := fingerprint.Compute(f, projectRoot)

			b.Findings[fp.ID] = BaselineFinding{
				FingerprintID: fp.ID,
				RuleID:        string(f.RuleID),
				Severity:      strings.ToLower(f.Severity.String()),
				FilePath:      fp.Components.FilePath,
				Title:         f.Title,
				SuppressedAt:  now,
			}
			b.TotalFindings++
		}
	}

	return b
}

func LoadFromFile(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}

	if b.Version == "" {
		return nil, fmt.Errorf("invalid baseline file: missing version")
	}

	return &b, nil
}

func (b *Baseline) SaveToFile(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}

	return nil
}

func (b *Baseline) Contains(fingerprintID string) bool {
	_, ok := b.Findings[fingerprintID]
	return ok
}

// Suppress adds a finding to the baseline.
func (b *Baseline) Suppress(f analyzer.Finding, projectRoot, note string) {
	fp := fingerprint.Compute(f, projectRoot)
	b.Findings[fp.ID] = BaselineFinding{
		FingerprintID: fp.ID,
		RuleID:        string(f.RuleID),
		Severity:      strings.ToLower(f.Severity.String()),
		FilePath:      fp.Components.FilePath,
		Title:         f.Title,
		SuppressedAt:  time.Now().UTC(),
		Note:          note,
	}
	b.TotalFindings = len(b.Findings)
}

func (b *Baseline) Remove(fingerprintID string) bool {
	if _, ok := b.Findings[fingerprintID]; !ok {
		return false
	}
	delete(b.Findings, fingerprintID)
	b.TotalFindings = len(b.Findings)
	return true
}

func (b *Baseline) Stats() BaselineStats {
	bySeverity := make(map[string]int)
	byRule := make(map[string]int)

	for _, f := range b.Findings {
		bySeverity[f.Severity]++
		byRule[f.RuleID]++
	}

	return BaselineStats{
		Total:       len(b.Findings),
		BySeverity:  bySeverity,
		ByRule:      byRule,
		CreatedAt:   b.CreatedAt,
		ToolVersion: b.ToolVersion,
	}
}

type BaselineStats struct {
	Total       int
	BySeverity  map[string]int
	ByRule      map[string]int
	CreatedAt   time.Time
	ToolVersion string
}

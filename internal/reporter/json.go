package reporter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// solsec scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
// solsec scan . --format json > report.json  # artifact olarak sakla
type JSONReporter struct {
	out    io.Writer
	pretty bool
}

func NewJSON(out io.Writer, pretty bool) *JSONReporter {
	return &JSONReporter{out: out, pretty: pretty}
}

type JSONReport struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Tool          ToolInfo        `json:"tool"`
	Summary       JSONSummary     `json:"summary"`
	Findings      []JSONFinding   `json:"findings"`
	ByFile        []FileFindings  `json:"by_file"`
	Errors        []AnalysisError `json:"errors,omitempty"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type JSONSummary struct {
	TotalFiles    int            `json:"total_files"`
	FilesWithBugs int            `json:"files_with_bugs"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByDetector    map[string]int `json:"by_detector"`
	ByConfidence  map[string]int `json:"by_confidence"`
}

// JSONFinding is the JSON representation of one finding.
type JSONFinding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id,omitempty"`
	DetectorName   string   `json:"detector"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Filepath       string   `json:"file"`
	Line           int      `json:"line"`
	CodeSnippet    string   `json:"code_snippet,omitempty"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Tags           []string `json:"tags,omitempty"`
}

type FileFindings struct {
	Filepath string        `json:"file"`
	Findings []JSONFinding `json:"findings"`
	Count    int           `json:"count"`
}

type AnalysisError struct {
	Filepath string `json:"file"`
	Error    string `json:"error"`
}

func (r *JSONReporter) Report(results []analyzer.AnalysisResult) error {
	stats := ComputeStats(results)
	report := r.buildReport(results, stats)

	var data []byte
	var err error

	if r.pretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		return err
	}

	_, err = r.out.Write(data)
	return err
}

func (r *JSONReporter) buildReport(
	results []analyzer.AnalysisResult,
	stats SummaryStats,
) JSONReport {

	// Flat finding listesi
	var allFindings []JSONFinding
	var byFile []FileFindings
	var errors []AnalysisError

	for _, result := range results {
		if result.Error != nil {
			errors = append(errors, AnalysisError{
				Filepath: result.Filepath,
				Error:    result.Error.Error(),
			})
			continue
		}

		fileFindings := make([]JSONFinding, 0, len(result.Findings))
		for _, f := range result.Findings {
			jf := toJSONFinding(f)
			allFindings = append(allFindings, jf)
			fileFindings = append(fileFindings, jf)
		}

		if len(fileFindings) > 0 {
			byFile = append(byFile, FileFindings{
				Filepath: result.Filepath,
				Findings: fileFindings,
				Count:    len(fileFindings),
			})
		}
	}

	// BySeverity map'ini string key'li yap
	bySevStr := make(map[string]int)
	for sev, count := range stats.BySeverity {
		bySevStr[sev.String()] = count
	}

	byConfStr := make(map[string]int)
	for conf, count := range stats.ByConfidence {
		byConfStr[conf.String()] = count
	}

	return JSONReport{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		Tool: ToolInfo{
			Name:    "solsec",
			Version: "0.2.0",
		},
		Summary: JSONSummary{
			TotalFiles:    stats.TotalFiles,
			FilesWithBugs: stats.FilesWithBugs,
			TotalFindings: stats.TotalFindings,
			BySeverity:    bySevStr,
			ByDetector:    stats.ByDetector,
			ByConfidence:  byConfStr,
		},
		Findings: allFindings,
		ByFile:   byFile,
		Errors:   errors,
	}
}

func toJSONFinding(f analyzer.Finding) JSONFinding {
	enrichFinding(&f)
	return JSONFinding{
		ID:             findingID(f),
		RuleID:         effectiveRuleID(f),
		DetectorName:   f.DetectorName,
		Title:          f.Title,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		Filepath:       f.Filepath,
		Line:           f.Line,
		CodeSnippet:    f.CodeSnippet,
		Severity:       f.Severity.String(),
		Confidence:     f.Confidence.String(),
		Tags:           f.Tags,
	}
}

func findingID(f analyzer.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%d:%s", effectiveRuleID(f), f.Filepath, f.Line, f.Title)
	return fmt.Sprintf("%x", h.Sum(nil))[:12] // 12 hex karakter yeterli
}

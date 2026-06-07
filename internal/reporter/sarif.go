package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// SARIF (Static Analysis Results Interchange Format) nedir?
//
//	solsec scan . --format sarif > results.sarif
//	# GitHub Actions'da:
//	- uses: github/codeql-action/upload-sarif@v2
//	  with:
//	    sarif_file: results.sarif
//
// SARIF schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
type SARIFReporter struct {
	out      io.Writer
	repoRoot string
}

func NewSARIF(out io.Writer, repoRoot string) *SARIFReporter {
	return &SARIFReporter{out: out, repoRoot: repoRoot}
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Results   []sarifResult   `json:"results"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
	// Precision finding'in kesinlik seviyesi
	Precision string `json:"precision,omitempty"`
	// SecuritySeverity CVSS benzeri 0-10 skor
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"` // error, warning, note
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

func (r *SARIFReporter) Report(results []analyzer.AnalysisResult) error {
	rules, ruleIndex := r.buildRules(results)

	// SARIF results
	var sarifResults []sarifResult
	var artifacts []sarifArtifact
	seenFiles := make(map[string]bool)

	for _, result := range results {
		if !seenFiles[result.Filepath] {
			seenFiles[result.Filepath] = true
			artifacts = append(artifacts, sarifArtifact{
				Location: sarifArtifactLocation{
					URI:       r.toURI(result.Filepath),
					URIBaseID: "%SRCROOT%",
				},
			})
		}

		for _, f := range result.Findings {
			enrichFinding(&f)
			ruleID := effectiveRuleID(f)
			ruleIdx := ruleIndex[ruleID]
			_ = ruleIdx

			sr := sarifResult{
				RuleID: ruleID,
				Level:  r.severityToLevel(f.Severity),
				Message: sarifMessage{
					Text: truncate(f.Title+": "+f.Description, 500),
				},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{
								URI:       r.toURI(f.Filepath),
								URIBaseID: "%SRCROOT%",
							},
							Region: sarifRegion{
								StartLine: max(f.Line, 1),
							},
						},
					},
				},
				PartialFingerprints: map[string]string{
					"primaryLocationLineHash": findingID(f),
				},
			}
			sarifResults = append(sarifResults, sr)
		}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "solsec",
						Version:        "0.2.0",
						InformationURI: "https://github.com/ayb-blc/solsec",
						Rules:          rules,
					},
				},
				Results:   sarifResults,
				Artifacts: artifacts,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	_, err = r.out.Write(data)
	return err
}

func (r *SARIFReporter) buildRules(
	results []analyzer.AnalysisResult,
) ([]sarifRule, map[string]int) {

	seen := make(map[string]analyzer.Finding)
	for _, result := range results {
		for _, f := range result.Findings {
			enrichFinding(&f)
			key := effectiveRuleID(f)
			if _, ok := seen[key]; !ok {
				seen[key] = f
			}
		}
	}

	rules := make([]sarifRule, 0, len(seen))
	ruleIndex := make(map[string]int)

	for name, f := range seen {
		enrichFinding(&f)
		ruleIndex[name] = len(rules)
		displayName := detectorDisplayName(f.DetectorName)
		shortDescription := f.Title
		fullDescription := f.Description
		precision := confidenceToPrecision(f.Confidence)
		securitySeverity := severityToCVSS(f.Severity)
		tags := f.Tags
		if f.Rule != nil {
			displayName = f.Rule.Name
			shortDescription = f.Rule.ShortDescription
			fullDescription = f.Rule.FullDescription
			precision = f.Rule.SARIFPrecision()
			securitySeverity = fmt.Sprintf("%.1f", f.Rule.CVSSScore())
			tags = append(append([]string(nil), f.Rule.Tags...), f.Tags...)
		}
		rules = append(rules, sarifRule{
			ID:   name,
			Name: displayName,
			ShortDescription: sarifMessage{
				Text: shortDescription,
			},
			FullDescription: sarifMessage{
				Text: fullDescription,
			},
			Properties: sarifRuleProperties{
				Tags:             tags,
				Precision:        precision,
				SecuritySeverity: securitySeverity,
			},
		})
	}

	return rules, ruleIndex
}

func (r *SARIFReporter) severityToLevel(sev analyzer.Severity) string {
	switch sev {
	case analyzer.Critical, analyzer.High:
		return "error"
	case analyzer.Medium:
		return "warning"
	default:
		return "note"
	}
}

func (r *SARIFReporter) toURI(filepath string) string {
	uri := strings.ReplaceAll(filepath, "\\", "/")
	if r.repoRoot != "" {
		uri = strings.TrimPrefix(uri, r.repoRoot)
		uri = strings.TrimPrefix(uri, "/")
	}
	return uri
}

func severityToCVSS(sev analyzer.Severity) string {
	switch sev {
	case analyzer.Critical:
		return "9.8"
	case analyzer.High:
		return "7.5"
	case analyzer.Medium:
		return "5.0"
	case analyzer.Low:
		return "2.5"
	default:
		return "0.0"
	}
}

func confidenceToPrecision(conf analyzer.Confidence) string {
	switch conf {
	case analyzer.ConfidenceHigh:
		return "high"
	case analyzer.ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

func detectorDisplayName(name string) string {
	replacer := strings.NewReplacer("-", " ", "_", " ")
	return strings.Title(replacer.Replace(name))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

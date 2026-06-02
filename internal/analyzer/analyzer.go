package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ayb-blc/solsec/internal/rules"
)

// Detector is the contract implemented by each security detector.
type Detector interface {
	Name() string
	Description() string
	Severity() Severity
	Analyze(lines []string, source, filepath string) ([]Finding, error)
}

// Analyzer orchestrates file scanning and detector execution.
type Analyzer struct {
	detectors []Detector
	config    Config
}

type Config struct {
	// Workers controls file-level parallelism. A value of 0 uses a conservative default.
	Workers int

	MinSeverity Severity

	IgnorePatterns []string

	OnlyDetectors []string
}

func New(detectors []Detector, config Config) *Analyzer {
	return &Analyzer{
		detectors: detectors,
		config:    config,
	}
}

// AnalysisResult contains the findings produced for one file.
type AnalysisResult struct {
	Filepath string
	Findings []Finding
	Error    error
}

// ScanDirectory scans all Solidity files under dir.
func (a *Analyzer) ScanDirectory(dir string) ([]AnalysisResult, error) {
	var files []string
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root = filepath.Clean(root)
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if filepath.Clean(abs) != root && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sol") {
			if a.isIgnored(path, root) {
				return nil
			}
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("directory walk failed: %w", err)
	}

	return a.ScanFiles(files)
}

// ScanFiles analyzes the provided file list in parallel.
func (a *Analyzer) ScanFiles(files []string) ([]AnalysisResult, error) {
	numWorkers := a.config.Workers
	if numWorkers <= 0 {
		numWorkers = 4
	}

	jobs := make(chan string, len(files))
	results := make(chan AnalysisResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filepath := range jobs {
				result := a.AnalyzeFile(filepath)
				results <- result
			}
		}()
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []AnalysisResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults, nil
}

// AnalyzeFile analyzes one Solidity file with all configured detectors.
func (a *Analyzer) AnalyzeFile(filePath string) AnalysisResult {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return AnalysisResult{Filepath: filePath, Error: fmt.Errorf("read error: %w", err)}
	}

	source := string(content)
	lines := strings.Split(source, "\n")

	var findings []Finding

	for _, detector := range a.detectors {
		if len(a.config.OnlyDetectors) > 0 && !contains(a.config.OnlyDetectors, detector.Name()) {
			continue
		}

		detectorFindings, err := detector.Analyze(lines, source, filePath)
		if err != nil {
			continue
		}

		for _, f := range detectorFindings {
			normalizeRuleID(&f)
			if f.Severity >= a.config.MinSeverity {
				findings = append(findings, f)
			}
		}
	}

	return AnalysisResult{
		Filepath: filePath,
		Findings: findings,
	}
}

func normalizeRuleID(f *Finding) {
	if f == nil {
		return
	}
	if f.RuleID != "" && strings.HasPrefix(string(f.RuleID), "SOLSEC-") {
		if f.Rule == nil {
			if rule, ok := rules.Global().Get(f.RuleID); ok {
				f.Rule = rule
			}
		}
		return
	}

	for _, rule := range rules.Global().ByDetector(f.DetectorName) {
		f.RuleID = rule.ID
		f.Rule = rule
		return
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (a *Analyzer) isIgnored(path, root string) bool {
	if len(a.config.IgnorePatterns) == 0 {
		return false
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)

	for _, pattern := range a.config.IgnorePatterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if globMatch(pattern, rel) || globMatch(pattern, base) {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
				return true
			}
		}
		if strings.HasPrefix(pattern, "**/") && globMatch(strings.TrimPrefix(pattern, "**/"), base) {
			return true
		}
	}
	return false
}

func globMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

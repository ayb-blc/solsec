package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
	"github.com/ayb-blc/solsec/internal/rules"
)

// Detector is the contract implemented by each security detector.
type Detector interface {
	Name() string
	Description() string
	Severity() Severity
	Analyze(lines []string, source, filepath string) ([]Finding, error)
}

// GraphAwareDetector is implemented by detectors that can use project-level
// context such as inheritance, modifiers, function signatures, and state ops.
// Detectors that do not implement it continue to use the legacy Analyze path.
type GraphAwareDetector interface {
	AnalyzeWithGraph(
		lines []string,
		source string,
		filepath string,
		graph *inheritancegraph.Graph,
	) ([]Finding, error)
}

// Analyzer orchestrates file scanning and detector execution.
type Analyzer struct {
	detectors        []Detector
	config           Config
	inheritanceGraph *inheritancegraph.Graph
}

type Config struct {
	// Workers controls file-level parallelism. A value of 0 uses a conservative default.
	Workers int

	MinSeverity Severity

	IgnorePatterns []string

	OnlyDetectors []string
}

// RunConfig describes a project-level analysis run.
type RunConfig struct {
	RootDir         string
	ExcludePatterns []string
	Workers         int
	MinSeverity     Severity
	Experimental    bool
}

// Report is the project-level result returned by Run.
type Report struct {
	Results  []AnalysisResult
	Findings []Finding
	Graph    *inheritancegraph.Graph
}

func New(detectors []Detector, config Config) *Analyzer {
	return &Analyzer{
		detectors: detectors,
		config:    config,
	}
}

// Run scans a project directory after building project-level context.
func (a *Analyzer) Run(cfg RunConfig) (*Report, error) {
	if cfg.RootDir == "" {
		cfg.RootDir = "."
	}
	if cfg.Workers > 0 {
		a.config.Workers = cfg.Workers
	}
	a.config.MinSeverity = cfg.MinSeverity

	files, root, err := a.collectSolFiles(cfg.RootDir, cfg.ExcludePatterns)
	if err != nil {
		return nil, err
	}
	a.buildInheritanceGraph(root, files)

	results, err := a.ScanFiles(files)
	if err != nil {
		return nil, err
	}

	findings := flattenFindings(results)
	return &Report{
		Results:  results,
		Findings: findings,
		Graph:    a.InheritanceGraph(),
	}, nil
}

// InheritanceGraph returns the project graph built for the latest directory run.
func (a *Analyzer) InheritanceGraph() *inheritancegraph.Graph {
	if a.inheritanceGraph == nil {
		return inheritancegraph.NewGraph()
	}
	return a.inheritanceGraph
}

// BuildInheritanceGraph builds project context for an explicit file set.
// It is useful for tooling that controls file collection but still wants
// graph-aware detectors to see the whole project during per-file analysis.
func (a *Analyzer) BuildInheritanceGraph(root string, files []string) {
	a.buildInheritanceGraph(root, files)
}

// AnalysisResult contains the findings produced for one file.
type AnalysisResult struct {
	Filepath string
	Findings []Finding
	Error    error
}

// ScanDirectory scans all Solidity files under dir.
func (a *Analyzer) ScanDirectory(dir string) ([]AnalysisResult, error) {
	files, root, err := a.collectSolFiles(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("directory walk failed: %w", err)
	}

	a.buildInheritanceGraph(root, files)
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

	if a.inheritanceGraph == nil {
		root := filepath.Dir(filePath)
		a.buildInheritanceGraph(root, []string{filePath})
	}

	source := string(content)
	lines := strings.Split(source, "\n")

	var findings []Finding

	for _, detector := range a.detectors {
		if len(a.config.OnlyDetectors) > 0 && !contains(a.config.OnlyDetectors, detector.Name()) {
			continue
		}

		var detectorFindings []Finding
		var err error
		if graphDetector, ok := detector.(GraphAwareDetector); ok {
			detectorFindings, err = graphDetector.AnalyzeWithGraph(
				lines,
				source,
				filePath,
				a.InheritanceGraph(),
			)
		} else {
			detectorFindings, err = detector.Analyze(lines, source, filePath)
		}
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

func (a *Analyzer) collectSolFiles(dir string, excludePatterns []string) ([]string, string, error) {
	var files []string
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
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
			if filepath.Clean(abs) != root && shouldSkipDefaultPath(path, d.Name()) {
				return filepath.SkipDir
			}
			if filepath.Clean(abs) != root && matchesAnyExclude(path, root, excludePatterns) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".sol") {
			return nil
		}
		if shouldSkipDefaultPath(path, filepath.Base(path)) {
			return nil
		}
		if a.isIgnored(path, root) || matchesAnyExclude(path, root, excludePatterns) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, root, err
}

func (a *Analyzer) buildInheritanceGraph(root string, files []string) {
	builder := inheritancegraph.NewBuilder(root)
	graph, err := builder.BuildFromFiles(files)
	if err != nil {
		graph = inheritancegraph.NewGraph()
	}
	a.inheritanceGraph = graph
}

func flattenFindings(results []AnalysisResult) []Finding {
	var findings []Finding
	for _, result := range results {
		findings = append(findings, result.Findings...)
	}
	return findings
}

func matchesAnyExclude(path, root string, patterns []string) bool {
	if len(patterns) == 0 {
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

	for _, pattern := range patterns {
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
	}
	return false
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

func shouldSkipDefaultPath(path, name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}

	normalized := filepath.ToSlash(path)
	lowerName := strings.ToLower(name)
	lowerPath := strings.ToLower(normalized)

	if lowerName == "node_modules" || lowerName == "lib" || lowerName == "vendor" ||
		lowerName == "out" || lowerName == "artifacts" || lowerName == "cache" ||
		lowerName == "mock" || lowerName == "mocks" {
		return true
	}

	if strings.Contains(lowerPath, "/mock/") || strings.Contains(lowerPath, "/mocks/") ||
		strings.Contains(lowerPath, "/test/") || strings.Contains(lowerPath, "/tests/") {
		return true
	}

	return strings.HasSuffix(lowerName, "_test.sol") ||
		strings.HasSuffix(lowerName, ".t.sol")
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

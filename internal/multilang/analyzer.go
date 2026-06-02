package multilang

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/parser"
)

type Analyzer struct {
	registry  *parser.ParserRegistry
	detectors []detectors.UnifiedDetector
	config    analyzer.Config
}

func New(
	registry *parser.ParserRegistry,
	dets []detectors.UnifiedDetector,
	config analyzer.Config,
) *Analyzer {
	if registry == nil {
		registry = parser.DefaultRegistry()
	}
	return &Analyzer{
		registry:  registry,
		detectors: dets,
		config:    config,
	}
}

func Default() *Analyzer {
	return New(
		parser.DefaultRegistry(),
		[]detectors.UnifiedDetector{
			detectors.NewUnifiedReentrancyDetector(),
			detectors.NewUnifiedTxOriginDetector(),
		},
		analyzer.Config{Workers: 4},
	)
}

func (a *Analyzer) ScanDirectory(dir string) ([]analyzer.AnalysisResult, error) {
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
			name := d.Name()
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if filepath.Clean(abs) != root && (name == "node_modules" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if isSupportedContractPath(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("directory walk failed: %w", err)
	}

	return a.ScanFiles(files)
}

func (a *Analyzer) ScanFiles(files []string) ([]analyzer.AnalysisResult, error) {
	workers := a.config.Workers
	if workers <= 0 {
		workers = 4
	}

	jobs := make(chan string, len(files))
	results := make(chan analyzer.AnalysisResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				results <- a.AnalyzeFile(path)
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

	all := make([]analyzer.AnalysisResult, 0, len(files))
	for r := range results {
		all = append(all, r)
	}
	return all, nil
}

func (a *Analyzer) AnalyzeFile(path string) analyzer.AnalysisResult {
	ast, err := a.registry.Parse(path)
	if err != nil {
		return analyzer.AnalysisResult{Filepath: path, Error: err}
	}

	var findings []analyzer.Finding
	for _, det := range a.detectors {
		if !supportsUnifiedLanguage(det.SupportedLanguages(), ast.Language) {
			continue
		}
		found, err := det.AnalyzeUnified(ast)
		if err != nil {
			return analyzer.AnalysisResult{Filepath: path, Error: err}
		}
		for _, f := range found {
			if f.Severity >= a.config.MinSeverity {
				findings = append(findings, f)
			}
		}
	}

	return analyzer.AnalysisResult{Filepath: path, Findings: findings}
}

func isSupportedContractPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".sol" || ext == ".vy"
}

func supportsUnifiedLanguage(supported []parser.Language, lang parser.Language) bool {
	for _, s := range supported {
		if s == lang {
			return true
		}
	}
	return false
}

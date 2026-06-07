// internal/cache/incremental.go

package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// IncrementalAnalyzer cache + git diff entegrasyonu ile
type IncrementalAnalyzer struct {
	cache      *Cache
	underlying FileAnalyzer
	opts       IncrementalOptions
}

type FileAnalyzer interface {
	AnalyzeFile(path string) analyzer.AnalysisResult
}

type IncrementalOptions struct {
	UseGitDiff bool

	GitStrategy DiffStrategy

	GitRef string

	ForceReanalyze []string

	Workers int

	ToolVersion string

	DetectorVersions map[string]string

	// Verbose cache hit/miss logla
	Verbose bool
}

// AnalysisReport bir analiz oturumunun sonucu.
type AnalysisReport struct {
	Results     []analyzer.AnalysisResult
	CacheHits   int
	CacheMisses int
	Skipped     int // parse edilemeyen dosyalar
}

func NewIncrementalAnalyzer(
	cacheDir string,
	underlying FileAnalyzer,
	opts IncrementalOptions,
) (*IncrementalAnalyzer, error) {
	if opts.ToolVersion == "" {
		opts.ToolVersion = "0.2.0"
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}

	c, err := New(cacheDir, opts.ToolVersion)
	if err != nil {
		return nil, fmt.Errorf("cache init: %w", err)
	}

	return &IncrementalAnalyzer{
		cache:      c,
		underlying: underlying,
		opts:       opts,
	}, nil
}

// ScanDirectory bir dizini incremental olarak tarar.
func (ia *IncrementalAnalyzer) ScanDirectory(dir string) (*AnalysisReport, error) {
	allFiles, err := collectSmartContractFiles(dir)
	if err != nil {
		return nil, err
	}

	toAnalyze, cached, skipped, err := ia.selectFilesForAnalysis(dir, allFiles)
	if err != nil {
		return nil, err
	}

	if ia.opts.Verbose {
		fmt.Printf("[cache] %d files to analyze, %d cache hits, %d skipped\n",
			len(toAnalyze), len(cached), skipped)
	}

	newResults := ia.analyzeFiles(toAnalyze)

	var cachedResults []analyzer.AnalysisResult
	for _, entry := range cached {
		cachedResults = append(cachedResults, ia.entryToResult(entry))
	}

	for i, result := range newResults {
		if result.Error != nil {
			continue
		}
		entry := ia.resultToEntry(result)
		if err := ia.cache.Set(result.Filepath, entry); err != nil && ia.opts.Verbose {
			fmt.Printf("[cache] write error for %s: %v\n", result.Filepath, err)
		}
		_ = i
	}

	return &AnalysisReport{
		Results:     append(newResults, cachedResults...),
		CacheHits:   len(cached),
		CacheMisses: len(toAnalyze),
		Skipped:     skipped,
	}, nil
}

// ScanFile incrementally analyzes a single smart contract file.
func (ia *IncrementalAnalyzer) ScanFile(path string) (*AnalysisReport, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if entry, err := ia.cache.Get(abs); err == nil && entry != nil && !ia.matchesForceReanalyze(abs) {
		return &AnalysisReport{
			Results:   []analyzer.AnalysisResult{ia.entryToResult(entry)},
			CacheHits: 1,
		}, nil
	}

	result := ia.underlying.AnalyzeFile(abs)
	if result.Error == nil {
		if err := ia.cache.Set(abs, ia.resultToEntry(result)); err != nil && ia.opts.Verbose {
			fmt.Printf("[cache] write error for %s: %v\n", abs, err)
		}
	}
	return &AnalysisReport{
		Results:     []analyzer.AnalysisResult{result},
		CacheMisses: 1,
	}, nil
}

// - toAnalyze: yeniden analiz edilmesi gerekenler
func (ia *IncrementalAnalyzer) selectFilesForAnalysis(
	dir string,
	allFiles []string,
) (toAnalyze []string, cached []*CacheEntry, skipped int, err error) {

	var changedFiles map[string]bool
	if ia.opts.UseGitDiff && IsGitRepo(dir) {
		changed, err := ia.getChangedFilesFromGit(dir)
		if err != nil && ia.opts.Verbose {
			fmt.Printf("[cache] git diff failed, falling back to hash check: %v\n", err)
		} else {
			changedFiles = make(map[string]bool, len(changed))
			for _, f := range changed {
				abs, err := filepath.Abs(f)
				if err == nil {
					f = abs
				}
				changedFiles[filepath.Clean(f)] = true
			}
		}
	}

	for _, file := range allFiles {
		abs, err := filepath.Abs(file)
		if err == nil {
			file = abs
		}
		file = filepath.Clean(file)

		if ia.matchesForceReanalyze(file) {
			toAnalyze = append(toAnalyze, file)
			continue
		}

		if changedFiles != nil {
			if changedFiles[file] {
				toAnalyze = append(toAnalyze, file)
				continue
			}
			if entry, err := ia.cache.Get(file); err == nil && entry != nil {
				cached = append(cached, entry)
				continue
			}
			// Git diff mode intentionally scans only changed files. If an
			// unchanged file is not cached, skip it instead of turning a PR
			// scan into a full cold-start project scan.
			skipped++
			continue
		}

		if entry, err := ia.cache.Get(file); err == nil && entry != nil {
			cached = append(cached, entry)
			continue
		}
		toAnalyze = append(toAnalyze, file)
	}

	return toAnalyze, cached, skipped, nil
}

func (ia *IncrementalAnalyzer) analyzeFiles(files []string) []analyzer.AnalysisResult {
	if len(files) == 0 {
		return nil
	}

	jobs := make(chan string, len(files))
	results := make(chan analyzer.AnalysisResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < ia.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				results <- ia.underlying.AnalyzeFile(path)
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

	var out []analyzer.AnalysisResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

func (ia *IncrementalAnalyzer) getChangedFilesFromGit(dir string) ([]string, error) {
	gd, err := NewGitDiff(dir)
	if err != nil {
		return nil, err
	}

	if ia.opts.GitRef != "" {
		return gd.ChangedFilesSince(ia.opts.GitRef)
	}
	return gd.ChangedFiles(ia.opts.GitStrategy)
}

func (ia *IncrementalAnalyzer) matchesForceReanalyze(file string) bool {
	for _, pattern := range ia.opts.ForceReanalyze {
		matched, _ := filepath.Match(pattern, filepath.Base(file))
		if matched {
			return true
		}
		if strings.Contains(file, pattern) {
			return true
		}
	}
	return false
}

func (ia *IncrementalAnalyzer) resultToEntry(
	result analyzer.AnalysisResult,
) *CacheEntry {
	entry := &CacheEntry{
		Filepath:         result.Filepath,
		FilePath:         result.Filepath,
		FindingCount:     len(result.Findings),
		DetectorVersions: ia.opts.DetectorVersions,
		Findings:         make([]CachedFinding, len(result.Findings)),
	}

	for i, f := range result.Findings {
		entry.Findings[i] = CachedFinding{
			DetectorName:   f.DetectorName,
			Title:          f.Title,
			Description:    f.Description,
			Recommendation: f.Recommendation,
			Filepath:       f.Filepath,
			Line:           f.Line,
			CodeSnippet:    f.CodeSnippet,
			Severity:       int(f.Severity),
			Confidence:     int(f.Confidence),
			Tags:           f.Tags,
		}
	}

	return entry
}

func (ia *IncrementalAnalyzer) entryToResult(
	entry *CacheEntry,
) analyzer.AnalysisResult {
	filepath := entry.Filepath
	if filepath == "" {
		filepath = entry.FilePath
	}
	result := analyzer.AnalysisResult{
		Filepath: filepath,
		Findings: make([]analyzer.Finding, len(entry.Findings)),
	}
	if len(entry.Findings) == 0 {
		return result
	}

	for i, cf := range entry.Findings {
		if result.Filepath == "" {
			result.Filepath = cf.Filepath
		}
		result.Findings[i] = analyzer.Finding{
			DetectorName:   cf.DetectorName,
			Title:          cf.Title,
			Description:    cf.Description,
			Recommendation: cf.Recommendation,
			Filepath:       cf.Filepath,
			Line:           cf.Line,
			CodeSnippet:    cf.CodeSnippet,
			Severity:       analyzer.Severity(cf.Severity),
			Confidence:     analyzer.Confidence(cf.Confidence),
			Tags:           cf.Tags,
		}
	}
	return result
}

func collectSmartContractFiles(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if IsSmartContractFile(dir) {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return nil, err
			}
			return []string{filepath.Clean(abs)}, nil
		}
		return nil, nil
	}

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
			if filepath.Clean(abs) != root && shouldSkipDefaultSmartContractPath(path, name) {
				return filepath.SkipDir
			}
			return nil
		}
		if IsSmartContractFile(path) && !shouldSkipDefaultSmartContractPath(path, filepath.Base(path)) {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			files = append(files, filepath.Clean(abs))
		}
		return nil
	})
	return files, err
}

func shouldSkipDefaultSmartContractPath(path, name string) bool {
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

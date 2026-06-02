package analyzer

// FileAnalyzer is the small interface required by wrappers such as incremental
// and project-level analyzers. Analyzer already satisfies it through
// AnalyzeFile.
type FileAnalyzer interface {
	AnalyzeFile(path string) AnalysisResult
}

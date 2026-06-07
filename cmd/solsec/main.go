// cmd/solsec/main.go

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/cache"
	solconfig "github.com/ayb-blc/solsec/internal/config"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/formal"
	"github.com/ayb-blc/solsec/internal/intercontract"
	"github.com/ayb-blc/solsec/internal/onchain"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/reporter"
	"github.com/ayb-blc/solsec/internal/rules"
	"github.com/ayb-blc/solsec/internal/suppression"
	"github.com/spf13/cobra"
)

const toolVersion = "0.2.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

var (
	outputFormat  string
	outputFile    string
	minSeverity   string
	failOn        string
	onlyDetectors []string
	workers       int
	noColor       bool
	verbose       bool
	prettyJSON    bool
	repoRoot      string
	projectName   string
	experimental  bool
	exitCode      int

	incrementalMode bool
	useGitDiff      bool
	gitRef          string
	gitStrategy     string
	cacheDir        string
	clearCache      bool
	showCacheStats  bool

	interContractMode bool
	interContractRoot string

	formalMode        bool
	formalDryRun      bool
	formalOutputDir   string
	formalTools       string
	formalTimeout     int
	formalMaxTargets  int
	formalMinPriority string

	onChainMode      bool
	onChainAddresses []string
	onChainNetwork   string
	etherscanAPIKey  string
	onChainLocalPath string

	configPath string
)

var rootCmd = &cobra.Command{
	Use:           "solsec",
	Short:         "Solidity smart contract security analyzer",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `solsec is a static analysis tool for detecting security vulnerabilities
in Solidity smart contracts. It checks for common issues like reentrancy,
tx.origin misuse, delegatecall risks, and more.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan Solidity files or directories for vulnerabilities",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userConfig, loadedConfigPath, err := loadUserConfig(configPath, args[0])
		if err != nil {
			return err
		}
		applyConfigDefaults(cmd, userConfig)

		minSev, err := parseSeverityFlag(minSeverity)
		if err != nil {
			return err
		}
		failSev, err := parseSeverityFlag(failOn)
		if err != nil {
			return err
		}

		validationRegistry := detectors.AllRegistry()
		if err := validateDetectorNames(onlyDetectors, validationRegistry.Names()); err != nil {
			return err
		}
		registry := detectors.DefaultRegistry()
		if experimental {
			registry = analyzer.NewRegistry(append(detectors.DefaultDetectors(), detectors.ExperimentalDetectors()...)...)
			if !noColor {
				fmt.Fprintln(os.Stderr, "Experimental mode enabled: storage-gap-missing and override-removes-restriction are active.")
			}
		}
		if len(onlyDetectors) > 0 {
			registry = validationRegistry
		}

		cfg := analyzer.Config{
			Workers:        workers,
			OnlyDetectors:  onlyDetectors,
			MinSeverity:    minSev,
			IgnorePatterns: userConfig.Exclude,
		}

		a := analyzer.New(registry.Detectors(), cfg)

		info, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("path error: %w", err)
		}

		resolvedCacheDir, err := resolveCacheDir(cacheDir, args[0], info)
		if err != nil {
			return err
		}
		if showCacheStats {
			c, err := cache.New(resolvedCacheDir, toolVersion)
			if err != nil {
				return err
			}
			stats := c.Stats()
			fmt.Printf("Cache dir:     %s\n", stats.Dir)
			fmt.Printf("Cache entries: %d\n", stats.EntryCount)
			fmt.Printf("Cache size:    %d bytes\n", stats.SizeBytes)
			return nil
		}
		if clearCache {
			c, err := cache.New(resolvedCacheDir, toolVersion)
			if err != nil {
				return err
			}
			if err := c.Clear(); err != nil {
				return fmt.Errorf("clear cache: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Cache cleared: %s\n", resolvedCacheDir)
			return nil
		}

		var results []analyzer.AnalysisResult
		if interContractMode {
			root := args[0]
			if interContractRoot != "" {
				root = interContractRoot
			} else if !info.IsDir() {
				root = filepath.Dir(args[0])
			}

			opts := intercontract.DefaultPipelineOptions()
			opts.MinSeverity = minSev
			pipeline := intercontract.NewInterContractPipeline(parser.DefaultRegistry(), opts)

			pipelineResult, err := pipeline.Analyze(root)
			if err != nil {
				return err
			}
			if verbose {
				pipelineResult.PrintStats()
			}
			results = pipelineResult.ToAnalysisResults()
		} else if incrementalMode || useGitDiff {
			strategy, err := parseGitStrategy(gitStrategy)
			if err != nil {
				return err
			}
			opts := cache.IncrementalOptions{
				UseGitDiff:       useGitDiff,
				GitStrategy:      strategy,
				GitRef:           gitRef,
				Workers:          workers,
				ToolVersion:      toolVersion,
				DetectorVersions: detectorVersions(registry.Detectors()),
				Verbose:          verbose,
			}
			ia, err := cache.NewIncrementalAnalyzer(resolvedCacheDir, a, opts)
			if err != nil {
				return err
			}

			var report *cache.AnalysisReport
			if info.IsDir() {
				report, err = ia.ScanDirectory(args[0])
			} else {
				report, err = ia.ScanFile(args[0])
			}
			if err != nil {
				return err
			}
			results = report.Results
			if verbose {
				fmt.Fprintf(os.Stderr,
					"[incremental] cache hits: %d, analyzed: %d, skipped: %d\n",
					report.CacheHits,
					report.CacheMisses,
					report.Skipped,
				)
			}
		} else if info.IsDir() {
			results, err = a.ScanDirectory(args[0])
		} else {
			result := a.AnalyzeFile(args[0])
			results = []analyzer.AnalysisResult{result}
		}
		if err != nil {
			return err
		}

		if onChainMode {
			addresses, err := parseOnChainAddresses(onChainAddresses)
			if err != nil {
				return err
			}

			apiKey := strings.TrimSpace(etherscanAPIKey)
			if apiKey == "" {
				apiKey = strings.TrimSpace(os.Getenv("ETHERSCAN_API_KEY"))
			}

			localPath := onChainLocalPath
			if localPath == "" {
				localPath = args[0]
			}

			opts := onchain.DefaultOnChainPipelineOpts(apiKey, onchain.Network(onChainNetwork))
			opts.LocalSourcePath = localPath
			opts.MinSeverity = minSev

			onChainPipeline := onchain.NewOnChainPipeline(opts)
			onChainResult, err := onChainPipeline.AnalyzeAddresses(addresses)
			if err != nil {
				return err
			}
			if verbose {
				onChainResult.PrintStats()
			}
			results = append(results, onChainResult.ToAnalysisResults()...)
		}

		results = applyRuleOverrides(results, userConfig)
		results = filterExcludedResults(results, userConfig.Exclude, args[0])
		suppressionEngine := suppression.NewEngine(userConfig)
		registerSuppressionSources(suppressionEngine, results)
		for _, warning := range suppressionEngine.ConfigWarnings() {
			if verbose {
				fmt.Fprintf(os.Stderr, "config warning: %s\n", warning)
			}
		}
		var suppressed int
		results, suppressed = suppressionEngine.FilterResults(results)
		if verbose {
			if loadedConfigPath != "" {
				fmt.Fprintf(os.Stderr, "[config] loaded: %s\n", loadedConfigPath)
			}
			if suppressed > 0 {
				fmt.Fprintf(os.Stderr, "[suppression] suppressed findings: %d\n", suppressed)
			}
		}

		if formalMode {
			priority, err := parseFuzzPriorityFlag(formalMinPriority)
			if err != nil {
				return err
			}
			tools, err := parseFormalTools(formalTools)
			if err != nil {
				return err
			}
			fOpts := formal.PipelineOpts{
				RunnerOptions: formal.RunnerOptions{
					Tools:        tools,
					Timeout:      time.Duration(formalTimeout) * time.Second,
					MaxTargets:   formalMaxTargets,
					OnlyPriority: priority,
					DryRun:       formalDryRun,
				},
				OutputDir: formalOutputDir,
			}
			fPipeline := formal.NewFormalPipeline(fOpts)
			fResult, err := fPipeline.Run(collectFindings(results))
			if err != nil {
				fmt.Fprintf(os.Stderr, "formal verification error: %v\n", err)
			} else {
				results = append(results, formalResultToAnalysisResults(fResult)...)
				if verbose {
					fmt.Fprintf(os.Stderr,
						"[formal] targets: %d, violations: %d, generated scripts: %d\n",
						len(fResult.Targets),
						fResult.Summary.Violations,
						len(fResult.GeneratedScripts),
					)
				}
			}
		}

		baselineExitCode := -1
		if baselineFile != "" {
			projectRootForBaseline := args[0]
			if !info.IsDir() {
				projectRootForBaseline = filepath.Dir(args[0])
			}
			results, baselineExitCode, err = applyBaselineMode(results, baselineFile, projectRootForBaseline, failSev)
			if err != nil {
				return err
			}
		}

		reporterOpts := reporter.Options{
			Format:      reporter.Format(outputFormat),
			Output:      outputFile,
			NoColor:     noColor,
			Verbose:     verbose,
			Pretty:      prettyJSON,
			RepoRoot:    repoRoot,
			ProjectName: projectName,
			FailOn:      failSev,
		}

		r, out, err := reporter.New(reporterOpts)
		if err != nil {
			return err
		}

		if err := r.Report(results); err != nil {
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}

		stats := reporter.ComputeStats(results)
		if baselineExitCode >= 0 {
			exitCode = baselineExitCode
		} else {
			exitCode = reporter.ExitCode(stats, reporterOpts.FailOn)
		}
		if reporter.HasAnalysisErrors(results) {
			exitCode = 2
		}
		return nil
	},
}

var explainCmd = &cobra.Command{
	Use:   "explain [detector-name]",
	Short: "Explain what a detector checks and why it matters",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := detectors.DefaultRegistry()
		name := strings.TrimSpace(args[0])

		for _, detector := range registry.Detectors() {
			if detector.Name() == name {
				fmt.Printf("%s\n\n", detector.Name())
				fmt.Printf("Severity: %s\n", detector.Severity())
				fmt.Printf("Description: %s\n", detector.Description())
				return nil
			}
		}

		return fmt.Errorf("unknown detector %q (available: %s)", name, strings.Join(sortedNames(registry.Names()), ", "))
	},
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, sarif, markdown")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file (default: stdout)")
	scanCmd.Flags().StringVarP(&minSeverity, "min-severity", "s", "low", "Minimum severity: info, low, medium, high, critical")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "medium", "Exit with code 1 if findings at or above this severity exist")
	scanCmd.Flags().StringSliceVarP(&onlyDetectors, "detectors", "d", nil, "Run only these detectors (comma-separated)")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 0, "Number of parallel workers (0 = auto)")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show recommendations in output")
	scanCmd.Flags().BoolVar(&prettyJSON, "pretty", false, "Pretty-print JSON output")
	scanCmd.Flags().StringVar(&repoRoot, "repo-root", "", "Repository root for SARIF relative paths")
	scanCmd.Flags().StringVar(&projectName, "project", "Unknown", "Project name for Markdown report")
	scanCmd.Flags().BoolVar(&experimental, "experimental", false, "Enable experimental detectors (storage-gap-missing, override-removes-restriction)")
	scanCmd.Flags().BoolVarP(&incrementalMode, "incremental", "i", false, "Enable cache-based incremental analysis")
	scanCmd.Flags().BoolVar(&useGitDiff, "git-diff", false, "Analyze changed files from git diff; unchanged files are reused from cache when available")
	scanCmd.Flags().StringVar(&gitRef, "git-ref", "", "Analyze files changed since this git ref (branch, tag, or commit)")
	scanCmd.Flags().StringVar(&gitStrategy, "git-strategy", "default", "Git diff strategy: default, staged, unstaged, uncommitted, last-commit")
	scanCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory (default: user cache dir scoped by project path)")
	scanCmd.Flags().BoolVar(&clearCache, "clear-cache", false, "Clear the analysis cache for this target")
	scanCmd.Flags().BoolVar(&showCacheStats, "cache-stats", false, "Show analysis cache statistics")
	scanCmd.Flags().BoolVar(&interContractMode, "inter-contract", false, "Enable cross-contract project analysis")
	scanCmd.Flags().StringVar(&interContractRoot, "inter-contract-root", "", "Project root for cross-contract analysis (default: scan path or parent directory)")
	scanCmd.Flags().BoolVar(&formalMode, "formal", false, "Enable formal verification bridge (Echidna/Manticore)")
	scanCmd.Flags().BoolVar(&formalDryRun, "formal-dry-run", false, "Generate verification scripts without running external tools")
	scanCmd.Flags().StringVar(&formalOutputDir, "formal-output", "formal-verification", "Output directory for formal verification artifacts")
	scanCmd.Flags().StringVar(&formalTools, "formal-tools", "echidna,manticore", "Comma-separated formal tools: echidna, manticore")
	scanCmd.Flags().IntVar(&formalTimeout, "formal-timeout", 300, "Timeout per formal tool in seconds")
	scanCmd.Flags().IntVar(&formalMaxTargets, "formal-max-targets", 5, "Maximum number of formal targets to verify")
	scanCmd.Flags().StringVar(&formalMinPriority, "formal-min-priority", "medium", "Minimum formal target priority: low, medium, high, critical")
	scanCmd.Flags().StringVar(&configPath, "config", "", "Path to .solsec.yml config file")
	initOnChainFlags()

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(explainCmd)
}

func parseSeverityFlag(s string) (analyzer.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return analyzer.Critical, nil
	case "high":
		return analyzer.High, nil
	case "medium":
		return analyzer.Medium, nil
	case "low":
		return analyzer.Low, nil
	case "info":
		return analyzer.Info, nil
	default:
		return analyzer.Info, fmt.Errorf("unknown severity %q (valid: info, low, medium, high, critical)", s)
	}
}

func validateDetectorNames(requested, available []string) error {
	if len(requested) == 0 {
		return nil
	}

	valid := make(map[string]struct{}, len(available))
	for _, name := range available {
		valid[name] = struct{}{}
	}

	var unknown []string
	for _, name := range requested {
		if _, ok := valid[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown detector(s): %s (available: %s)",
			strings.Join(unknown, ", "),
			strings.Join(sortedNames(available), ", "),
		)
	}
	return nil
}

func sortedNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

func parseGitStrategy(s string) (cache.DiffStrategy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return cache.DiffStrategyDefault, nil
	case "staged":
		return cache.DiffStrategyStaged, nil
	case "unstaged":
		return cache.DiffStrategyUnstaged, nil
	case "uncommitted":
		return cache.DiffStrategyAllUncommitted, nil
	case "last-commit":
		return cache.DiffStrategyLastCommit, nil
	default:
		return cache.DiffStrategyDefault, fmt.Errorf("unknown git strategy %q (valid: default, staged, unstaged, uncommitted, last-commit)", s)
	}
}

func detectorVersions(detectors []analyzer.Detector) map[string]string {
	versions := make(map[string]string, len(detectors))
	for _, detector := range detectors {
		versions[detector.Name()] = toolVersion
	}
	return versions
}

func resolveCacheDir(flagValue, target string, info os.FileInfo) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	root := target
	if !info.IsDir() {
		root = filepath.Dir(target)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return cache.DefaultDir(abs), nil
}

func parseFormalTools(s string) ([]formal.Tool, error) {
	var tools []formal.Tool
	for _, raw := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "":
			continue
		case string(formal.ToolEchidna):
			tools = append(tools, formal.ToolEchidna)
		case string(formal.ToolManticore):
			tools = append(tools, formal.ToolManticore)
		default:
			return nil, fmt.Errorf("unknown formal tool %q (valid: echidna, manticore)", name)
		}
	}
	if len(tools) == 0 {
		return formal.DefaultRunnerOptions().Tools, nil
	}
	return tools, nil
}

func parseFuzzPriorityFlag(s string) (formal.FuzzPriority, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return formal.PriorityCritical, nil
	case "high":
		return formal.PriorityHigh, nil
	case "medium", "":
		return formal.PriorityMedium, nil
	case "low":
		return formal.PriorityLow, nil
	default:
		return formal.PriorityMedium, fmt.Errorf("unknown formal priority %q (valid: low, medium, high, critical)", s)
	}
}

func collectFindings(results []analyzer.AnalysisResult) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.Filepath == "" {
				finding.Filepath = result.Filepath
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func formalResultToAnalysisResults(result *formal.FormalResult) []analyzer.AnalysisResult {
	if result == nil {
		return nil
	}

	findingsByFile := make(map[string][]analyzer.Finding)
	for _, finding := range result.ConfirmedFindings {
		filepath := finding.Filepath
		if filepath == "" {
			filepath = "<formal-verification>"
		}
		findingsByFile[filepath] = append(findingsByFile[filepath], finding)
	}

	if len(result.GeneratedScripts) > 0 {
		findingsByFile["<formal-verification>"] = append(findingsByFile["<formal-verification>"], analyzer.Finding{
			DetectorName:   "formal",
			Title:          "Formal verification scripts generated",
			Description:    strings.Join(result.GeneratedScripts, "\n"),
			Recommendation: "Run the generated Echidna/Manticore artifacts to validate the static-analysis finding with dynamic or symbolic evidence.",
			Severity:       analyzer.Info,
			Confidence:     analyzer.ConfidenceHigh,
			Tags:           []string{"formal", "dry-run"},
		})
	}

	if len(findingsByFile) == 0 {
		return nil
	}

	files := make([]string, 0, len(findingsByFile))
	for filepath := range findingsByFile {
		files = append(files, filepath)
	}
	sort.Strings(files)

	converted := make([]analyzer.AnalysisResult, 0, len(files))
	for _, filepath := range files {
		converted = append(converted, analyzer.AnalysisResult{
			Filepath: filepath,
			Findings: findingsByFile[filepath],
		})
	}
	return converted
}

func loadUserConfig(path, target string) (*solconfig.Config, string, error) {
	if strings.TrimSpace(path) != "" {
		return solconfig.LoadFile(path)
	}
	return solconfig.Load(target)
}

func applyConfigDefaults(cmd *cobra.Command, cfg *solconfig.Config) {
	if cfg == nil {
		return
	}
	flags := cmd.Flags()
	if !flags.Changed("min-severity") && cfg.Scan.Severity != "" {
		minSeverity = cfg.Scan.Severity
	}
	if !flags.Changed("fail-on") && cfg.Scan.FailOn != "" {
		failOn = cfg.Scan.FailOn
	}
	if !flags.Changed("workers") && cfg.Scan.Workers > 0 {
		workers = cfg.Scan.Workers
	}
	if !flags.Changed("format") && cfg.Output.Format != "" {
		outputFormat = cfg.Output.Format
	}
	if !flags.Changed("no-color") {
		noColor = cfg.Output.NoColor
	}
	if !flags.Changed("detectors") {
		onlyDetectors = configuredDetectors(cfg)
	}
}

func configuredDetectors(cfg *solconfig.Config) []string {
	if cfg == nil {
		return nil
	}
	disabled := make(map[string]struct{}, len(cfg.Detectors.Disable))
	for _, name := range cfg.Detectors.Disable {
		disabled[strings.TrimSpace(name)] = struct{}{}
	}

	if len(cfg.Detectors.Enable) > 0 {
		var out []string
		for _, name := range cfg.Detectors.Enable {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, skip := disabled[name]; skip {
				continue
			}
			out = append(out, name)
		}
		return out
	}

	if len(disabled) == 0 {
		return nil
	}
	registry := detectors.DefaultRegistry()
	var out []string
	for _, name := range registry.Names() {
		if _, skip := disabled[name]; !skip {
			out = append(out, name)
		}
	}
	return out
}

func applyRuleOverrides(results []analyzer.AnalysisResult, cfg *solconfig.Config) []analyzer.AnalysisResult {
	if cfg == nil || len(cfg.Rules.Override) == 0 {
		return results
	}
	for resultIndex := range results {
		for findingIndex := range results[resultIndex].Findings {
			finding := &results[resultIndex].Findings[findingIndex]
			id := finding.RuleID
			if id == "" {
				id = rules.RuleID(finding.DetectorName)
			}
			override, ok := cfg.Rules.Override[string(id)]
			if !ok {
				continue
			}
			if override.Severity != "" {
				if severity, err := parseSeverityFlag(override.Severity); err == nil {
					finding.Severity = severity
				}
			}
			if override.Confidence != "" {
				if confidence, err := parseConfidenceFlag(override.Confidence); err == nil {
					finding.Confidence = confidence
				}
			}
		}
	}
	return results
}

func parseConfidenceFlag(s string) (analyzer.Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return analyzer.ConfidenceHigh, nil
	case "medium":
		return analyzer.ConfidenceMedium, nil
	case "low":
		return analyzer.ConfidenceLow, nil
	default:
		return analyzer.ConfidenceMedium, fmt.Errorf("unknown confidence %q (valid: low, medium, high)", s)
	}
}

func registerSuppressionSources(engine *suppression.Engine, results []analyzer.AnalysisResult) {
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if result.Filepath == "" {
			continue
		}
		if _, ok := seen[result.Filepath]; ok {
			continue
		}
		seen[result.Filepath] = struct{}{}
		content, err := os.ReadFile(result.Filepath)
		if err != nil {
			continue
		}
		engine.RegisterFile(result.Filepath, string(content))
	}
}

func filterExcludedResults(results []analyzer.AnalysisResult, patterns []string, target string) []analyzer.AnalysisResult {
	if len(patterns) == 0 {
		return results
	}
	root := target
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		root = filepath.Dir(target)
	}
	absRoot, err := filepath.Abs(root)
	if err == nil {
		root = absRoot
	}

	filtered := make([]analyzer.AnalysisResult, 0, len(results))
	for _, result := range results {
		if isExcludedPath(result.Filepath, root, patterns) {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func isExcludedPath(path, root string, patterns []string) bool {
	if path == "" || strings.HasPrefix(path, "<") {
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
		if matchConfigGlob(pattern, rel) || matchConfigGlob(pattern, base) {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
				return true
			}
		}
		if strings.HasPrefix(pattern, "**/") && matchConfigGlob(strings.TrimPrefix(pattern, "**/"), base) {
			return true
		}
	}
	return false
}

func matchConfigGlob(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

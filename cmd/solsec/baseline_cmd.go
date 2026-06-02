package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/baseline"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/exitcode"
	"github.com/ayb-blc/solsec/internal/fingerprint"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage finding baselines for CI/CD",
	Long: `Baseline management for incremental CI/CD security scanning.

Workflow:
  1. solsec baseline create ./contracts
     Creates solsec-baseline.json from current findings

  2. solsec scan ./contracts --baseline solsec-baseline.json
     Only NEW findings (not in baseline) break the CI

  3. solsec baseline show
     Inspect what's currently suppressed

  4. solsec baseline update ./contracts
     Merge new findings into existing baseline`,
}

// --- baseline create ---

var baselineCreateCmd = &cobra.Command{
	Use:   "create [path]",
	Short: "Create a new baseline from current findings",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineCreate,
}

var (
	baselineOutput string
	baselineNote   string
	baselineMinSev string
)

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	target := args[0]
	absTarget, _ := filepath.Abs(target)

	fmt.Fprintf(os.Stderr, "Scanning %s to create baseline...\n", target)

	minSev, err := parseSeverityFlag(baselineMinSev)
	if err != nil {
		return err
	}

	cfg := analyzer.Config{
		Workers:     workers,
		MinSeverity: minSev,
	}
	a := analyzer.New(detectors.DefaultRegistry().Detectors(), cfg)

	var results []analyzer.AnalysisResult
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access %q: %w", target, err)
	}

	if info.IsDir() {
		results, err = a.ScanDirectory(target)
	} else {
		results = []analyzer.AnalysisResult{a.AnalyzeFile(target)}
	}
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	for i := range results {
		fingerprint.ComputeAll(results[i].Findings, absTarget)
	}

	b := baseline.Create(results, absTarget, toolVersion)
	if baselineNote != "" {
		for id, finding := range b.Findings {
			finding.Note = baselineNote
			b.Findings[id] = finding
		}
	}

	if baselineOutput == "" {
		baselineOutput = "solsec-baseline.json"
	}

	if err := b.SaveToFile(baselineOutput); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}

	stats := b.Stats()
	fmt.Printf("\n✅ Baseline created: %s\n", baselineOutput)
	fmt.Printf("   Findings suppressed: %d\n", stats.Total)
	fmt.Printf("   Created at: %s\n", stats.CreatedAt.Format(time.RFC3339))

	if stats.Total > 0 {
		fmt.Printf("\n   By severity:\n")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := stats.BySeverity[sev]; n > 0 {
				fmt.Printf("     %-10s %d\n", sev, n)
			}
		}
	}

	fmt.Printf("\nCommit %s to your repository.\n", baselineOutput)
	fmt.Printf("Future scans: solsec scan %s --baseline %s\n", target, baselineOutput)

	return nil
}

// --- baseline show ---

var baselineShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current baseline contents",
	RunE:  runBaselineShow,
}

var baselineShowFile string

func runBaselineShow(cmd *cobra.Command, args []string) error {
	if baselineShowFile == "" {
		baselineShowFile = "solsec-baseline.json"
	}

	b, err := baseline.LoadFromFile(baselineShowFile)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}

	stats := b.Stats()
	fmt.Printf("Baseline: %s\n", baselineShowFile)
	fmt.Printf("Created:  %s\n", stats.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Version:  %s (tool: %s)\n", b.Version, b.ToolVersion)
	fmt.Printf("Total:    %d suppressed findings\n\n", stats.Total)

	if stats.Total == 0 {
		fmt.Println("No findings in baseline.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tRULE ID\tSEVERITY\tFILE\tTITLE")
	fmt.Fprintln(w, "-----------\t-------\t--------\t----\t-----")

	for _, f := range b.Findings {
		title := f.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		note := ""
		if f.Note != "" {
			note = " [" + f.Note + "]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s%s\n",
			f.FingerprintID,
			f.RuleID,
			strings.ToUpper(f.Severity),
			truncatePath(f.FilePath, 30),
			title,
			note,
		)
	}
	w.Flush()

	return nil
}

// --- baseline update ---

var baselineUpdateCmd = &cobra.Command{
	Use:   "update [path]",
	Short: "Add new findings to existing baseline",
	Long: `Merge new findings from a scan into the existing baseline.
Useful for bulk-suppressing findings in legacy codebases.`,
	Args: cobra.ExactArgs(1),
	RunE: runBaselineUpdate,
}

var (
	baselineUpdateFile string
	baselineUpdateNote string
	baselineUpdateSev  string
)

func runBaselineUpdate(cmd *cobra.Command, args []string) error {
	target := args[0]
	absTarget, _ := filepath.Abs(target)

	if baselineUpdateFile == "" {
		baselineUpdateFile = "solsec-baseline.json"
	}

	b, err := baseline.LoadFromFile(baselineUpdateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No existing baseline, creating new one.\n")
		b = &baseline.Baseline{
			Version:     "1",
			CreatedAt:   time.Now().UTC(),
			ProjectRoot: absTarget,
			ToolVersion: toolVersion,
			Findings:    make(map[string]baseline.BaselineFinding),
		}
	}

	minSev, err := parseSeverityFlag(baselineUpdateSev)
	if err != nil {
		return err
	}

	cfg := analyzer.Config{
		Workers:     workers,
		MinSeverity: minSev,
	}
	a := analyzer.New(detectors.DefaultRegistry().Detectors(), cfg)

	var results []analyzer.AnalysisResult
	info, err := os.Stat(target)
	if err != nil {
		return err
	}

	if info.IsDir() {
		results, err = a.ScanDirectory(target)
	} else {
		results = []analyzer.AnalysisResult{a.AnalyzeFile(target)}
	}
	if err != nil {
		return err
	}

	diff := baseline.Diff(results, b, absTarget)

	added := 0
	for _, f := range diff.New {
		b.Suppress(f, absTarget, baselineUpdateNote)
		added++
	}

	if added == 0 {
		fmt.Println("No new findings to add to baseline.")
		return nil
	}

	if err := b.SaveToFile(baselineUpdateFile); err != nil {
		return err
	}

	fmt.Printf("✅ Baseline updated: %s\n", baselineUpdateFile)
	fmt.Printf("   Added: %d new finding(s)\n", added)
	fmt.Printf("   Total: %d suppressed finding(s)\n", len(b.Findings))

	return nil
}

// --- baseline remove ---

var baselineRemoveCmd = &cobra.Command{
	Use:   "remove <fingerprint-id>",
	Short: "Remove a finding from the baseline (force it to be reported again)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		file := "solsec-baseline.json"
		if baselineShowFile != "" {
			file = baselineShowFile
		}

		b, err := baseline.LoadFromFile(file)
		if err != nil {
			return err
		}

		fpID := args[0]
		if !b.Remove(fpID) {
			return fmt.Errorf("fingerprint %q not found in baseline", fpID)
		}

		if err := b.SaveToFile(file); err != nil {
			return err
		}

		fmt.Printf("✅ Removed %s from baseline\n", fpID)
		fmt.Printf("   Remaining: %d suppressed finding(s)\n", len(b.Findings))
		return nil
	},
}

func applyBaselineMode(
	results []analyzer.AnalysisResult,
	baselineFile string,
	projectRoot string,
	threshold analyzer.Severity,
) ([]analyzer.AnalysisResult, int, error) {

	absRoot, _ := filepath.Abs(projectRoot)

	for i := range results {
		fingerprint.ComputeAll(results[i].Findings, absRoot)
	}

	b, err := baseline.LoadFromFile(baselineFile)
	if err != nil {
		return nil, exitcode.AnalysisError, fmt.Errorf("load baseline: %w", err)
	}

	diff := baseline.Diff(results, b, absRoot)

	printBaselineDiffSummary(diff, threshold)

	code := exitcode.FromDiff(diff, threshold)
	return baselineDiffToResults(diff), code, nil
}

func baselineDiffToResults(diff *baseline.DiffResult) []analyzer.AnalysisResult {
	if diff == nil || len(diff.New) == 0 {
		return []analyzer.AnalysisResult{{Filepath: "new-findings"}}
	}

	byFile := make(map[string][]analyzer.Finding)
	for _, f := range diff.New {
		filepath := f.Filepath
		if filepath == "" {
			filepath = "new-findings"
		}
		byFile[filepath] = append(byFile[filepath], f)
	}

	results := make([]analyzer.AnalysisResult, 0, len(byFile))
	for filepath, findings := range byFile {
		results = append(results, analyzer.AnalysisResult{
			Filepath: filepath,
			Findings: findings,
		})
	}
	return results
}

func printBaselineDiffSummary(diff *baseline.DiffResult, threshold analyzer.Severity) {
	fmt.Printf("\n")

	if len(diff.New) == 0 {
		fmt.Printf("✅ No new findings (baseline: %d suppressed)\n", len(diff.Existing))
	} else {
		fmt.Printf("🔴 %d new finding(s) detected:\n", len(diff.New))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, f := range diff.New {
			marker := ""
			if f.Severity >= threshold {
				marker = " ← CI FAIL"
			}
			fmt.Fprintf(w, "  [%s] %s\t%s:%d%s\n",
				f.Severity, f.Title, truncatePath(f.Filepath, 30), f.Line, marker)
		}
		w.Flush()
	}

	if len(diff.Existing) > 0 {
		fmt.Printf("⚠️  %d suppressed finding(s) (in baseline — not failing CI)\n",
			len(diff.Existing))
	}

	if len(diff.Resolved) > 0 {
		fmt.Printf("✅ %d finding(s) resolved since baseline\n", len(diff.Resolved))
		for _, r := range diff.Resolved {
			fmt.Printf("   [%s] %s\n", r.RuleID, r.Title)
		}
	}
}

func truncatePath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	return "..." + path[len(path)-max+3:]
}

func init() {
	baselineCreateCmd.Flags().StringVarP(&baselineOutput, "output", "o",
		"solsec-baseline.json", "Output baseline file path")
	baselineCreateCmd.Flags().StringVar(&baselineNote, "note", "",
		"Note explaining why findings are suppressed")
	baselineCreateCmd.Flags().StringVar(&baselineMinSev, "min-severity", "low",
		"Minimum severity to include in baseline")

	baselineShowCmd.Flags().StringVarP(&baselineShowFile, "file", "f",
		"solsec-baseline.json", "Baseline file to inspect")

	baselineUpdateCmd.Flags().StringVarP(&baselineUpdateFile, "file", "f",
		"solsec-baseline.json", "Baseline file to update")
	baselineUpdateCmd.Flags().StringVar(&baselineUpdateNote, "note", "",
		"Note for newly suppressed findings")
	baselineUpdateCmd.Flags().StringVar(&baselineUpdateSev, "min-severity", "low",
		"Minimum severity to include")

	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineShowCmd)
	baselineCmd.AddCommand(baselineUpdateCmd)
	baselineCmd.AddCommand(baselineRemoveCmd)

	rootCmd.AddCommand(baselineCmd)

	scanCmd.Flags().StringVar(&baselineFile, "baseline", "",
		"Baseline file; only new findings will break CI")
}

var baselineFile string

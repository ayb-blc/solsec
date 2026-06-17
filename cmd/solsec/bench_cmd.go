// cmd/solsec/bench_cmd.go

package main

import (
	"fmt"
	"os"

	"github.com/ayb-blc/solsec/internal/bench"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/spf13/cobra"
)

var (
	benchRuns      int
	benchWarmup    int
	benchSave      string
	benchCompare   string
	benchThreshold float64
	benchVerbose   bool
)

var benchCmd = &cobra.Command{
	Use:   "bench <target>",
	Short: "Benchmark solsec scan performance on a directory",
	Long: `Measure scan performance: throughput, per-detector timing, and memory.

Examples:
  solsec bench ./contracts
  solsec bench ./contracts --runs 5 --warmup 2
  solsec bench ./contracts --save baseline.json
  solsec bench ./contracts --compare baseline.json --threshold 15`,

	Args: cobra.ExactArgs(1),
	RunE: runBench,
}

func init() {
	benchCmd.Flags().IntVar(&benchRuns, "runs", 3,
		"Number of measured runs")
	benchCmd.Flags().IntVar(&benchWarmup, "warmup", 1,
		"Number of warmup runs (discarded)")
	benchCmd.Flags().StringVar(&benchSave, "save", "",
		"Save results as baseline to this file")
	benchCmd.Flags().StringVar(&benchCompare, "compare", "",
		"Compare against this baseline file")
	benchCmd.Flags().Float64Var(&benchThreshold, "threshold", 10.0,
		"Regression threshold percentage (default 10%)")
	benchCmd.Flags().BoolVar(&benchVerbose, "verbose", false,
		"Show progress for each run")

	rootCmd.AddCommand(benchCmd)
}

func runBench(cmd *cobra.Command, args []string) error {
	target := args[0]

	fmt.Fprintf(os.Stderr, "solsec bench: scanning %s\n", target)
	fmt.Fprintf(os.Stderr, "  runs: %d  warmup: %d\n\n", benchRuns, benchWarmup)

	detectorList := detectors.DefaultDetectors()
	runner := &bench.Runner{
		Runs:    benchRuns,
		Warmup:  benchWarmup,
		Verbose: benchVerbose,
	}

	result, err := runner.Run(target, detectorList, nil)
	if err != nil {
		return fmt.Errorf("benchmark failed: %w", err)
	}

	// Print report
	bench.RenderText(result, os.Stdout)

	// Compare to baseline
	if benchCompare != "" {
		baseline, err := bench.LoadBaseline(benchCompare)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load baseline: %v\n", err)
		} else {
			regressions := bench.DetectRegressions(result, baseline, benchThreshold)
			bench.RenderRegressions(regressions, os.Stdout)
			if len(regressions) > 0 {
				os.Exit(1) // signal regression to CI
			}
		}
	}

	// Save baseline
	if benchSave != "" {
		if err := bench.SaveBaseline(result, benchSave); err != nil {
			return fmt.Errorf("saving baseline: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Baseline saved to %s\n", benchSave)
	}

	return nil
}

// Package formal bridges static analysis findings to external verification tools.
package formal

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RunnerOptions controls which formal tools are executed and how targets are
// filtered. OnlyPriority is a minimum threshold: for example "high" keeps high
// and critical targets.
type RunnerOptions struct {
	Tools           []Tool
	Timeout         time.Duration
	MaxTargets      int
	OnlyPriority    FuzzPriority
	DryRun          bool
	ScriptOutputDir string
	CorpusDir       string
	ManticorePath   string
	EchidnaPath     string
}

// DefaultRunnerOptions returns conservative defaults for local developer usage.
func DefaultRunnerOptions() RunnerOptions {
	return RunnerOptions{
		Tools:        []Tool{ToolEchidna, ToolManticore},
		Timeout:      5 * time.Minute,
		MaxTargets:   5,
		OnlyPriority: PriorityLow,
	}
}

// ToolRunner is the shared contract implemented by EchidnaRunner and
// ManticoreRunner. The runner keeps this interface small so adding another
// backend does not leak tool-specific details into the pipeline.
type ToolRunner interface {
	Tool() Tool
	IsAvailable() ToolAvailability
	Run(target *FuzzTarget) (*VerificationResult, error)
}

// Runner coordinates multiple formal backends over the same fuzz targets.
type Runner struct {
	opts    RunnerOptions
	runners map[Tool]ToolRunner
}

func NewRunner(opts RunnerOptions) *Runner {
	opts = normalizeRunnerOptions(opts)
	r := &Runner{
		opts:    opts,
		runners: make(map[Tool]ToolRunner, len(opts.Tools)),
	}

	for _, tool := range opts.Tools {
		switch tool {
		case ToolEchidna:
			echidna := NewEchidnaRunner(opts.EchidnaPath, opts.Timeout)
			echidna.corpusDir = opts.CorpusDir
			r.runners[ToolEchidna] = echidna
		case ToolManticore:
			manticore := NewManticoreRunner(opts.ManticorePath, opts.Timeout)
			manticore.outputDir = opts.ScriptOutputDir
			r.runners[ToolManticore] = manticore
		}
	}

	return r
}

func normalizeRunnerOptions(opts RunnerOptions) RunnerOptions {
	defaults := DefaultRunnerOptions()
	if len(opts.Tools) == 0 {
		opts.Tools = defaults.Tools
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaults.Timeout
	}
	if opts.MaxTargets <= 0 {
		opts.MaxTargets = defaults.MaxTargets
	}
	if opts.OnlyPriority == 0 {
		opts.OnlyPriority = defaults.OnlyPriority
	}
	return opts
}

// CheckAvailability reports availability for every requested tool, including
// unsupported names, so CLI output and tests can reason about the full request.
func (r *Runner) CheckAvailability() map[Tool]ToolAvailability {
	availability := make(map[Tool]ToolAvailability, len(r.opts.Tools))
	for _, tool := range r.opts.Tools {
		toolRunner, ok := r.runners[tool]
		if !ok {
			availability[tool] = ToolAvailability{
				Tool:      tool,
				Available: false,
				Error:     "unsupported formal verification tool",
			}
			continue
		}
		availability[tool] = toolRunner.IsAvailable()
	}
	return availability
}

// RunAll executes each available backend for each selected target.
func (r *Runner) RunAll(targets []*FuzzTarget) ([]*VerificationResult, error) {
	filtered := r.filterTargets(targets)
	if len(filtered) == 0 {
		return nil, nil
	}

	availability := r.CheckAvailability()
	var results []*VerificationResult
	var runErrors []string

	for _, target := range filtered {
		for _, tool := range r.opts.Tools {
			toolRunner, ok := r.runners[tool]
			if !ok {
				results = append(results, unavailableResult(tool, target, "unsupported formal verification tool"))
				continue
			}
			if avail := availability[tool]; !avail.Available {
				results = append(results, unavailableResult(tool, target, avail.Error))
				continue
			}

			result, err := toolRunner.Run(target)
			if err != nil {
				runErrors = append(runErrors, fmt.Sprintf("%s/%s: %v", tool, target.ContractName, err))
				results = append(results, unavailableResult(tool, target, err.Error()))
				continue
			}
			results = append(results, result)
		}
	}

	if len(results) == 0 && len(runErrors) > 0 {
		return nil, errors.New(strings.Join(runErrors, "; "))
	}
	return results, nil
}

func (r *Runner) filterTargets(targets []*FuzzTarget) []*FuzzTarget {
	filtered := make([]*FuzzTarget, 0, len(targets))
	for _, target := range targets {
		if target == nil {
			continue
		}
		if target.Priority < r.opts.OnlyPriority {
			continue
		}
		filtered = append(filtered, target)
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].Priority > filtered[j].Priority
	})

	if r.opts.MaxTargets > 0 && len(filtered) > r.opts.MaxTargets {
		filtered = filtered[:r.opts.MaxTargets]
	}
	return filtered
}

func unavailableResult(tool Tool, target *FuzzTarget, message string) *VerificationResult {
	return &VerificationResult{
		Tool:   tool,
		Target: target,
		Status: StatusError,
		Error:  message,
	}
}

func timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = DefaultRunnerOptions().Timeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

// VerificationSummary aggregates tool results for CLI reporting and tests.
type VerificationSummary struct {
	Total      int
	Safe       int
	Violations int
	Timeouts   int
	Errors     int
	Unknown    int
	Duration   time.Duration
}

func (s VerificationSummary) HasViolations() bool {
	return s.Violations > 0
}

func Summary(results []*VerificationResult) VerificationSummary {
	var summary VerificationSummary
	for _, result := range results {
		if result == nil {
			continue
		}
		summary.Total++
		summary.Duration += result.Duration
		switch result.Status {
		case StatusSafe:
			summary.Safe++
		case StatusViolation:
			summary.Violations++
		case StatusTimeout:
			summary.Timeouts++
		case StatusError:
			summary.Errors++
		default:
			summary.Unknown++
		}
	}
	return summary
}

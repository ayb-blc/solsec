package formal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type FormalPipeline struct {
	generator *SeedGenerator
	runner    *Runner
	opts      PipelineOpts
}

type PipelineOpts struct {
	RunnerOptions
	OutputDir     string
	ConfirmedOnly bool
}

func NewFormalPipeline(opts PipelineOpts) *FormalPipeline {
	return &FormalPipeline{
		generator: NewSeedGenerator(),
		runner:    NewRunner(opts.RunnerOptions),
		opts:      opts,
	}
}

type FormalResult struct {
	Targets []*FuzzTarget

	VerificationResults []*VerificationResult

	ConfirmedFindings []analyzer.Finding

	Summary VerificationSummary

	GeneratedScripts []string
}

func (p *FormalPipeline) Run(findings []analyzer.Finding) (*FormalResult, error) {
	result := &FormalResult{}

	targets := p.generator.Generate(findings)
	result.Targets = targets

	if len(targets) == 0 {
		return result, nil
	}

	if p.opts.OutputDir != "" {
		if err := os.MkdirAll(p.opts.OutputDir, 0o755); err != nil {
			return nil, fmt.Errorf("create output dir: %w", err)
		}
		p.opts.RunnerOptions.ScriptOutputDir = filepath.Join(p.opts.OutputDir, "scripts")
		p.opts.RunnerOptions.CorpusDir = filepath.Join(p.opts.OutputDir, "corpus")
		os.MkdirAll(p.opts.RunnerOptions.ScriptOutputDir, 0o755)
		os.MkdirAll(p.opts.RunnerOptions.CorpusDir, 0o755)
	}
	p.runner = NewRunner(p.opts.RunnerOptions)

	availability := p.runner.CheckAvailability()
	anyAvailable := false
	for _, avail := range availability {
		if avail.Available {
			anyAvailable = true
			break
		}
	}

	if p.opts.DryRun || !anyAvailable {
		scripts, err := p.generateScriptsOnly(targets)
		if err != nil {
			return nil, err
		}
		result.GeneratedScripts = scripts
		return result, nil
	}

	verResults, err := p.runner.RunAll(targets)
	if err != nil {
		return nil, fmt.Errorf("run tools: %w", err)
	}
	result.VerificationResults = verResults

	result.Summary = Summary(verResults)

	result.ConfirmedFindings = p.buildConfirmedFindings(verResults)

	return result, nil
}

func (p *FormalPipeline) generateScriptsOnly(
	targets []*FuzzTarget,
) ([]string, error) {
	var scripts []string

	runner := NewManticoreRunner("", 0)
	dir := p.opts.RunnerOptions.ScriptOutputDir
	if dir == "" {
		dir = "."
	}

	for _, target := range targets {
		if target.FunctionName == "" {
			continue
		}
		scriptPath := filepath.Join(dir,
			fmt.Sprintf("manticore_%s_%s.py",
				target.ContractName, target.FunctionName))

		if err := runner.WriteAnalysisScript(target, scriptPath); err != nil {
			continue
		}
		scripts = append(scripts, scriptPath)
	}

	echidnaRunner := NewEchidnaRunner("", 0)
	for _, target := range targets {
		if len(target.Properties) == 0 {
			continue
		}

		testFile, cleanup, err := echidnaRunner.prepareTestFile(target)
		if err != nil {
			continue
		}

		destPath := filepath.Join(dir,
			fmt.Sprintf("echidna_%s_%s.sol",
				target.ContractName, target.FunctionName))

		content, _ := os.ReadFile(testFile)
		cleanup()

		if err := os.WriteFile(destPath, content, 0o644); err != nil {
			continue
		}
		scripts = append(scripts, destPath)
	}

	return scripts, nil
}

func (p *FormalPipeline) buildConfirmedFindings(
	verResults []*VerificationResult,
) []analyzer.Finding {
	var findings []analyzer.Finding

	for _, vr := range verResults {
		if vr.Status != StatusViolation {
			continue
		}

		for _, violation := range vr.Violations {
			f := analyzer.Finding{
				DetectorName: string(vr.Tool) + "-verified",
				Title: fmt.Sprintf(
					"[VERIFIED] %s: %s",
					vr.Tool, violation.PropertyName,
				),
				Description: fmt.Sprintf(
					"%s\n\nThis vulnerability was formally verified by %s.\n"+
						"Original static analysis finding: %s",
					violation.Description,
					vr.Tool,
					vr.Target.SourceFinding.Title,
				),
				Recommendation: vr.Target.SourceFinding.Recommendation,
				Filepath:       vr.Target.ContractPath,
				Severity:       violation.Severity,
				Confidence:     analyzer.ConfidenceHigh,
				Tags: []string{
					"formal-verified",
					string(vr.Tool),
					string(vr.Target.SourceFinding.DetectorName),
				},
			}

			if violation.CounterExample != nil {
				f.Description += fmt.Sprintf(
					"\n\nCounter-example (%d calls):",
					len(violation.CounterExample.Calls),
				)
				for _, call := range violation.CounterExample.Calls {
					f.Description += fmt.Sprintf(
						"\n  %s.%s(%s) from %s",
						vr.Target.ContractName,
						call.Function,
						joinArgs(call.Args),
						call.Caller,
					)
				}
			}

			findings = append(findings, f)
		}
	}

	return findings
}

func joinArgs(args []string) string {
	result := ""
	for i, a := range args {
		if i > 0 {
			result += ", "
		}
		result += a
	}
	return result
}

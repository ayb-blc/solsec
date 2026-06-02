package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// SolcRunner executes a local solc binary.
type SolcRunner struct {
	// BinaryPath is the path to the solc binary.
	BinaryPath string

	AllowedPaths []string

	// RemappingPaths import remapping: "@openzeppelin/=node_modules/@openzeppelin/"
	RemappingPaths []string
}

func NewSolcRunner(binaryPath string) *SolcRunner {
	if binaryPath == "" {
		binaryPath = "solc" // PATH'ten ara
	}
	return &SolcRunner{BinaryPath: binaryPath}
}

type solcOutput struct {
	Sources map[string]struct {
		AST *SourceUnit `json:"AST"`
	} `json:"sources"`
	Errors []struct {
		Type     string `json:"type"`
		Message  string `json:"message"`
		Severity string `json:"severity"`
	} `json:"errors"`
}

func (r *SolcRunner) ParseFile(filepath string) (*SourceUnit, error) {
	args := []string{
		"--ast-compact-json",
		"--no-color",
		"--json", // JSON output
	}

	// Import remapping ekle
	args = append(args, r.RemappingPaths...)

	// Allowed paths ekle
	if len(r.AllowedPaths) > 0 {
		args = append(args, "--allow-paths", strings.Join(r.AllowedPaths, ","))
	}

	args = append(args, filepath)

	cmd := exec.Command(r.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	// solc output'unu parse et
	// Her ikisini de dene
	output := stdout.Bytes()
	if len(output) == 0 {
		output = stderr.Bytes()
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("solc produced no output for %s. Is solc installed? Error: %s",
			filepath, stderr.String())
	}

	var result solcOutput
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse solc output: %w\nRaw output: %s",
			err, string(output[:min(200, len(output))]))
	}

	// Fatal error'lar varsa raporla
	for _, e := range result.Errors {
		if e.Type == "Error" {
			// Error varsa AST eksik olabilir ama devam et
			// Warning'ler analizi durdurmaz
			fmt.Printf("solc warning/error for %s: %s\n", filepath, e.Message)
		}
	}

	// AST'yi bul
	for _, source := range result.Sources {
		if source.AST != nil {
			return source.AST, nil
		}
	}

	return nil, fmt.Errorf("no AST found in solc output for %s", filepath)
}

func (r *SolcRunner) IsAvailable() bool {
	cmd := exec.Command(r.BinaryPath, "--version")
	return cmd.Run() == nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

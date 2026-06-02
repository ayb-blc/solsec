package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_FindsYamlFile(t *testing.T) {
	dir := t.TempDir()
	content := `
version: "1"
scan:
  severity: high
  fail_on: critical
  workers: 8
detectors:
  enable:
    - reentrancy
    - tx-origin
  disable:
    - integer-overflow
exclude:
  - node_modules
  - test/mocks
ignore:
  - rule: SOLSEC-REENTRANCY-001
    file: contracts/LegacyVault.sol
    reason: "Legacy code, tracked in issue #42"
output:
  format: json
`
	if err := os.WriteFile(filepath.Join(dir, ".solsec.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, path, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if path == "" {
		t.Error("expected config path to be set")
	}

	if cfg.Scan.Severity != "high" {
		t.Errorf("severity = %q, want high", cfg.Scan.Severity)
	}
	if cfg.Scan.FailOn != "critical" {
		t.Errorf("fail_on = %q, want critical", cfg.Scan.FailOn)
	}
	if cfg.Scan.Workers != 8 {
		t.Errorf("workers = %d, want 8", cfg.Scan.Workers)
	}
	if len(cfg.Detectors.Enable) != 2 {
		t.Errorf("detectors.enable len = %d, want 2", len(cfg.Detectors.Enable))
	}
	if len(cfg.Detectors.Disable) != 1 {
		t.Errorf("detectors.disable len = %d, want 1", len(cfg.Detectors.Disable))
	}
	if len(cfg.Exclude) != 2 {
		t.Errorf("exclude len = %d, want 2", len(cfg.Exclude))
	}
	if len(cfg.Ignore) != 1 {
		t.Errorf("ignore len = %d, want 1", len(cfg.Ignore))
	}
	if cfg.Output.Format != "json" {
		t.Errorf("output.format = %q, want json", cfg.Output.Format)
	}
}

func TestLoad_DefaultsWhenNoFile(t *testing.T) {
	dir := t.TempDir()

	cfg, path, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path for default config, got %q", path)
	}
	if cfg.Scan.Workers != 4 {
		t.Errorf("default workers = %d, want 4", cfg.Scan.Workers)
	}
	if cfg.Scan.Severity != "low" {
		t.Errorf("default severity = %q, want low", cfg.Scan.Severity)
	}
}

func TestLoad_InvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	content := `scan:\n  severity: extreme\n`
	os.WriteFile(filepath.Join(dir, ".solsec.yml"), []byte(content), 0o644)

	_, _, err := Load(dir)
	if err == nil {
		t.Error("expected error for invalid severity value")
	}
}

func TestLoad_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	content := `output:\n  format: html\n`
	os.WriteFile(filepath.Join(dir, ".solsec.yml"), []byte(content), 0o644)

	_, _, err := Load(dir)
	if err == nil {
		t.Error("expected error for invalid output format")
	}
}

func TestLoad_MissingRuleInIgnore(t *testing.T) {
	dir := t.TempDir()
	content := `ignore:\n  - file: contracts/Vault.sol\n`
	os.WriteFile(filepath.Join(dir, ".solsec.yml"), []byte(content), 0o644)

	_, _, err := Load(dir)
	if err == nil {
		t.Error("expected error for ignore entry without rule field")
	}
}

func TestMerge_CLIOverridesConfig(t *testing.T) {
	base := &Config{
		Scan: ScanConfig{
			Severity: "low",
			Workers:  4,
		},
		Output: OutputConfig{
			Format: "text",
		},
	}

	flags := CLIFlags{
		Severity: "high",
		Workers:  8,
		Format:   "json",
	}

	merged := Merge(base, flags)

	if merged.Scan.Severity != "high" {
		t.Errorf("merged severity = %q, want high", merged.Scan.Severity)
	}
	if merged.Scan.Workers != 8 {
		t.Errorf("merged workers = %d, want 8", merged.Scan.Workers)
	}
	if merged.Output.Format != "json" {
		t.Errorf("merged format = %q, want json", merged.Output.Format)
	}
}

func TestMerge_EmptyFlagsKeepConfig(t *testing.T) {
	base := &Config{
		Scan: ScanConfig{
			Severity: "medium",
			Workers:  2,
		},
	}

	merged := Merge(base, CLIFlags{})

	if merged.Scan.Severity != "medium" {
		t.Errorf("empty flags should not override severity")
	}
	if merged.Scan.Workers != 2 {
		t.Errorf("empty flags should not override workers")
	}
}

func TestCandidateFilePriority(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, ".solsec.yml"), []byte("scan:\n  workers: 1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, ".solsec.yaml"), []byte("scan:\n  workers: 2\n"), 0o644)

	cfg, path, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != ".solsec.yml" {
		t.Errorf("expected .solsec.yml to take priority, got %s", path)
	}
	if cfg.Scan.Workers != 1 {
		t.Errorf("workers = %d, want 1 (from .solsec.yml)", cfg.Scan.Workers)
	}
}

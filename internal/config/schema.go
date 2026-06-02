// Package config loads and validates user-facing Solsec configuration.
package config

// Config mirrors .solsec.yml. The schema is intentionally small and explicit so
// CLI behavior remains predictable when new analysis engines are added.
type Config struct {
	Version   string
	Scan      ScanConfig
	Detectors DetectorConfig
	Rules     RulesConfig
	Exclude   []string
	Ignore    []IgnoreEntry
	Output    OutputConfig
}

type ScanConfig struct {
	Severity string
	FailOn   string
	Workers  int
	Timeout  int
}

type DetectorConfig struct {
	Enable  []string
	Disable []string
}

type RulesConfig struct {
	Override map[string]RuleOverride
}

type RuleOverride struct {
	Severity   string
	Confidence string
}

type IgnoreEntry struct {
	Rule     string
	File     string
	Function string
	Reason   string
	Expiry   string
}

type OutputConfig struct {
	Format  string
	NoColor bool
}

// CLIFlags contains optional command-line values used by Merge. Zero values
// mean "not provided" for the config package tests and simple callers.
type CLIFlags struct {
	Severity string
	FailOn   string
	Workers  int
	Format   string
	NoColor  *bool
}

func Default() *Config {
	return &Config{
		Version: "1",
		Scan: ScanConfig{
			Severity: "low",
			FailOn:   "medium",
			Workers:  4,
			Timeout:  60,
		},
		Rules: RulesConfig{
			Override: make(map[string]RuleOverride),
		},
		Output: OutputConfig{
			Format: "text",
		},
	}
}

func Merge(base *Config, flags CLIFlags) *Config {
	if base == nil {
		base = Default()
	}
	merged := clone(base)
	if flags.Severity != "" {
		merged.Scan.Severity = flags.Severity
	}
	if flags.FailOn != "" {
		merged.Scan.FailOn = flags.FailOn
	}
	if flags.Workers != 0 {
		merged.Scan.Workers = flags.Workers
	}
	if flags.Format != "" {
		merged.Output.Format = flags.Format
	}
	if flags.NoColor != nil {
		merged.Output.NoColor = *flags.NoColor
	}
	return merged
}

func clone(cfg *Config) *Config {
	out := *cfg
	out.Detectors.Enable = append([]string(nil), cfg.Detectors.Enable...)
	out.Detectors.Disable = append([]string(nil), cfg.Detectors.Disable...)
	out.Exclude = append([]string(nil), cfg.Exclude...)
	out.Ignore = append([]IgnoreEntry(nil), cfg.Ignore...)
	out.Rules.Override = make(map[string]RuleOverride, len(cfg.Rules.Override))
	for id, override := range cfg.Rules.Override {
		out.Rules.Override[id] = override
	}
	return &out
}

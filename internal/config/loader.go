package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var candidateFiles = []string{".solsec.yml", ".solsec.yaml"}

func Load(startDir string) (*Config, string, error) {
	path, err := findConfig(startDir)
	if err != nil {
		return nil, "", err
	}
	if path == "" {
		return Default(), "", nil
	}

	cfg, _, err := LoadFile(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}

func LoadFile(path string) (*Config, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := parseYAMLSubset(string(data), cfg); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if err := validate(cfg); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	return cfg, path, nil
}

// LoadFromFile is kept as a compatibility wrapper for older callers.
func LoadFromFile(path string) (*Config, error) {
	cfg, _, err := LoadFile(path)
	return cfg, err
}

func findConfig(startDir string) (string, error) {
	if startDir == "" {
		startDir = "."
	}
	info, err := os.Stat(startDir)
	if err != nil {
		return "", err
	}
	dir := startDir
	if !info.IsDir() {
		dir = filepath.Dir(startDir)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	for {
		for _, name := range candidateFiles {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

func parseYAMLSubset(content string, cfg *Config) error {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var section string
	var subsection string
	var currentIgnore *IgnoreEntry
	var currentOverride string

	for scanner.Scan() {
		raw := stripComment(scanner.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := leadingSpaces(raw)
		line := strings.TrimSpace(raw)

		if indent == 0 {
			currentIgnore = nil
			currentOverride = ""
			subsection = ""
			key, value, ok := splitKeyValue(line)
			if !ok {
				return fmt.Errorf("invalid top-level line %q", line)
			}
			section = key
			if value != "" {
				if section == "version" {
					cfg.Version = cleanScalar(value)
					continue
				}
				return fmt.Errorf("unexpected scalar for section %q", section)
			}
			continue
		}

		switch section {
		case "scan":
			if indent != 2 {
				return fmt.Errorf("invalid scan indentation in %q", line)
			}
			key, value, ok := splitKeyValue(line)
			if !ok {
				return fmt.Errorf("invalid scan line %q", line)
			}
			if err := setScanValue(&cfg.Scan, key, value); err != nil {
				return err
			}
		case "detectors":
			if indent == 2 {
				key, value, ok := splitKeyValue(line)
				if !ok {
					return fmt.Errorf("invalid detectors line %q", line)
				}
				if cleanScalar(value) == "[]" {
					subsection = ""
					continue
				}
				if value != "" {
					return fmt.Errorf("invalid detectors line %q", line)
				}
				subsection = key
				continue
			}
			if indent == 4 && strings.HasPrefix(line, "- ") {
				switch subsection {
				case "enable":
					cfg.Detectors.Enable = append(cfg.Detectors.Enable, cleanScalar(strings.TrimPrefix(line, "- ")))
				case "disable":
					cfg.Detectors.Disable = append(cfg.Detectors.Disable, cleanScalar(strings.TrimPrefix(line, "- ")))
				default:
					return fmt.Errorf("unknown detectors subsection %q", subsection)
				}
			}
		case "rules":
			if indent == 2 {
				key, value, ok := splitKeyValue(line)
				if !ok || value != "" || key != "override" {
					return fmt.Errorf("invalid rules line %q", line)
				}
				subsection = key
				continue
			}
			if subsection != "override" {
				return fmt.Errorf("unknown rules subsection %q", subsection)
			}
			if indent == 4 && strings.HasSuffix(line, ":") {
				currentOverride = strings.TrimSuffix(line, ":")
				if cfg.Rules.Override == nil {
					cfg.Rules.Override = make(map[string]RuleOverride)
				}
				cfg.Rules.Override[currentOverride] = RuleOverride{}
				continue
			}
			if indent == 6 {
				key, value, ok := splitKeyValue(line)
				if !ok || currentOverride == "" {
					return fmt.Errorf("invalid rule override line %q", line)
				}
				override := cfg.Rules.Override[currentOverride]
				switch key {
				case "severity":
					override.Severity = cleanScalar(value)
				case "confidence":
					override.Confidence = cleanScalar(value)
				default:
					return fmt.Errorf("unknown rule override key %q", key)
				}
				cfg.Rules.Override[currentOverride] = override
			}
		case "exclude":
			if indent == 2 && strings.HasPrefix(line, "- ") {
				cfg.Exclude = append(cfg.Exclude, cleanScalar(strings.TrimPrefix(line, "- ")))
			}
		case "ignore":
			if indent == 2 && strings.HasPrefix(line, "- ") {
				entry := IgnoreEntry{}
				currentIgnore = &entry
				cfg.Ignore = append(cfg.Ignore, entry)
				rest := strings.TrimSpace(strings.TrimPrefix(line, "- "))
				if rest != "" {
					key, value, ok := splitKeyValue(rest)
					if !ok {
						return fmt.Errorf("invalid ignore entry %q", line)
					}
					setIgnoreValue(&cfg.Ignore[len(cfg.Ignore)-1], key, value)
				}
				continue
			}
			if indent == 4 && currentIgnore != nil && len(cfg.Ignore) > 0 {
				key, value, ok := splitKeyValue(line)
				if !ok {
					return fmt.Errorf("invalid ignore line %q", line)
				}
				setIgnoreValue(&cfg.Ignore[len(cfg.Ignore)-1], key, value)
			}
		case "output":
			if indent != 2 {
				return fmt.Errorf("invalid output indentation in %q", line)
			}
			key, value, ok := splitKeyValue(line)
			if !ok {
				return fmt.Errorf("invalid output line %q", line)
			}
			if err := setOutputValue(&cfg.Output, key, value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown config section %q", section)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func setScanValue(scan *ScanConfig, key, value string) error {
	value = cleanScalar(value)
	switch key {
	case "severity":
		scan.Severity = value
	case "fail_on":
		scan.FailOn = value
	case "workers":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("scan.workers must be an integer")
		}
		scan.Workers = n
	case "timeout":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("scan.timeout must be an integer")
		}
		scan.Timeout = n
	default:
		return fmt.Errorf("unknown scan key %q", key)
	}
	return nil
}

func setOutputValue(output *OutputConfig, key, value string) error {
	value = cleanScalar(value)
	switch key {
	case "format":
		output.Format = value
	case "no_color":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("output.no_color must be true or false")
		}
		output.NoColor = b
	default:
		return fmt.Errorf("unknown output key %q", key)
	}
	return nil
}

func setIgnoreValue(entry *IgnoreEntry, key, value string) {
	value = cleanScalar(value)
	switch key {
	case "rule":
		entry.Rule = value
	case "file":
		entry.File = value
	case "function":
		entry.Function = value
	case "reason":
		entry.Reason = value
	case "expiry":
		entry.Expiry = value
	}
}

func validate(cfg *Config) error {
	if !validSeverity(cfg.Scan.Severity) {
		return fmt.Errorf("invalid scan.severity %q", cfg.Scan.Severity)
	}
	if !validSeverity(cfg.Scan.FailOn) {
		return fmt.Errorf("invalid scan.fail_on %q", cfg.Scan.FailOn)
	}
	if cfg.Scan.Workers < 0 {
		return fmt.Errorf("scan.workers cannot be negative")
	}
	if cfg.Scan.Timeout < 0 {
		return fmt.Errorf("scan.timeout cannot be negative")
	}
	if !validFormat(cfg.Output.Format) {
		return fmt.Errorf("invalid output.format %q", cfg.Output.Format)
	}
	for ruleID, override := range cfg.Rules.Override {
		if ruleID == "" {
			return fmt.Errorf("rules.override contains an empty rule id")
		}
		if override.Severity != "" && !validSeverity(override.Severity) {
			return fmt.Errorf("invalid severity override for %s: %q", ruleID, override.Severity)
		}
		if override.Confidence != "" && !validConfidence(override.Confidence) {
			return fmt.Errorf("invalid confidence override for %s: %q", ruleID, override.Confidence)
		}
	}
	for i, entry := range cfg.Ignore {
		if strings.TrimSpace(entry.Rule) == "" {
			return fmt.Errorf("ignore[%d].rule is required", i)
		}
	}
	return nil
}

func validSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validConfidence(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "medium", "high":
		return true
	default:
		return false
	}
}

func validFormat(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "text", "json", "sarif", "markdown":
		return true
	default:
		return false
	}
}

func splitKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

func cleanScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func leadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

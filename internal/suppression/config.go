package suppression

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ayb-blc/solsec/internal/config"
	"github.com/ayb-blc/solsec/internal/rules"
)

type ConfigSuppression struct {
	entries []resolvedEntry
	now     time.Time
}

type resolvedEntry struct {
	ruleID    rules.RuleID
	fileGlob  string
	function  string
	expiry    time.Time
	hasExpiry bool
	reason    string
}

func NewConfigSuppression(cfg *config.Config) (*ConfigSuppression, []string) {
	cs := &ConfigSuppression{now: time.Now()}
	var warnings []string

	for _, entry := range cfg.Ignore {
		re := resolvedEntry{
			ruleID:   rules.RuleID(entry.Rule),
			fileGlob: entry.File,
			function: entry.Function,
			reason:   entry.Reason,
		}

		if entry.Expiry != "" {
			t, err := time.Parse("2006-01-02", entry.Expiry)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"ignore rule %s: invalid expiry date %q (use YYYY-MM-DD)",
					entry.Rule, entry.Expiry,
				))
			} else {
				re.expiry = t
				re.hasExpiry = true
				if t.Before(cs.now) {
					warnings = append(warnings, fmt.Sprintf(
						"ignore rule %s: suppression expired on %s — consider removing it",
						entry.Rule, entry.Expiry,
					))
				}
			}
		}

		cs.entries = append(cs.entries, re)
	}

	return cs, warnings
}

func (cs *ConfigSuppression) IsSuppressed(
	ruleID rules.RuleID,
	filePath string,
	functionName string,
) bool {
	for _, entry := range cs.entries {
		if entry.ruleID != ruleID && entry.ruleID != "*" {
			continue
		}

		if entry.hasExpiry && entry.expiry.Before(cs.now) {
			continue
		}

		if entry.fileGlob != "" {
			matched, err := matchGlob(entry.fileGlob, filePath)
			if err != nil || !matched {
				continue
			}
		}

		if entry.function != "" && functionName != "" {
			if !strings.EqualFold(entry.function, functionName) {
				continue
			}
		}

		return true
	}
	return false
}

func matchGlob(pattern, filePath string) (bool, error) {
	// Forward slash normalize et
	filePath = filepath.ToSlash(filePath)
	pattern = filepath.ToSlash(pattern)

	if matched, err := filepath.Match(pattern, filePath); err != nil {
		return false, err
	} else if matched {
		return true, nil
	}

	baseName := filepath.Base(filePath)
	if matched, err := filepath.Match(pattern, baseName); err == nil && matched {
		return true, nil
	}

	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if strings.HasPrefix(filePath, prefix+"/") || filePath == prefix {
			return true, nil
		}
	}

	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		if matched, err := filepath.Match(suffix, baseName); err == nil && matched {
			return true, nil
		}
	}

	return false, nil
}

var _ = fmt.Sprintf

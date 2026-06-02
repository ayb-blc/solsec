package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func ExportToJSON(registry *Registry, path string) error {
	if registry == nil {
		registry = Global()
	}
	data, err := json.MarshalIndent(registry.All(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func ExportToYAML(registry *Registry, path string) error {
	if registry == nil {
		registry = Global()
	}

	var b strings.Builder
	for _, rule := range registry.All() {
		fmt.Fprintf(&b, "- id: %s\n", rule.ID)
		fmt.Fprintf(&b, "  name: %q\n", rule.Name)
		fmt.Fprintf(&b, "  severity: %s\n", rule.Severity)
		fmt.Fprintf(&b, "  confidence: %s\n", rule.Confidence)
		fmt.Fprintf(&b, "  category: %s\n", rule.Category)
		fmt.Fprintf(&b, "  language: %s\n", rule.Language)
		fmt.Fprintf(&b, "  detector_name: %s\n", rule.DetectorName)
		fmt.Fprintf(&b, "  enabled: %t\n", rule.Enabled)
		fmt.Fprintf(&b, "  short_description: %q\n", rule.ShortDescription)
		fmt.Fprintf(&b, "  remediation: %q\n", rule.Remediation)
		if len(rule.Tags) > 0 {
			fmt.Fprintf(&b, "  tags: [%s]\n", quoteList(rule.Tags))
		}
		if len(rule.References.SWC) > 0 || len(rule.References.CWE) > 0 {
			b.WriteString("  references:\n")
			if len(rule.References.SWC) > 0 {
				fmt.Fprintf(&b, "    swc: [%s]\n", quoteList(rule.References.SWC))
			}
			if len(rule.References.CWE) > 0 {
				fmt.Fprintf(&b, "    cwe: [%s]\n", quoteList(rule.References.CWE))
			}
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func quoteList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, fmt.Sprintf("%q", item))
	}
	return strings.Join(quoted, ", ")
}

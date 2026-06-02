// cmd/solsec/rules_cmd.go

package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ayb-blc/solsec/internal/rules"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List and inspect security rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := rules.Global()

		opts := rules.FilterOptions{
			IncludeDisabled: showDisabled,
		}
		if filterSeverity != "" {
			opts.Severities = []rules.Severity{rules.Severity(strings.ToLower(filterSeverity))}
		}
		if filterCategory != "" {
			opts.Categories = []rules.Category{rules.Category(strings.ToUpper(filterCategory))}
		}
		if searchQuery != "" {
			opts.SearchQuery = searchQuery
		}

		filtered := registry.Filter(opts)
		if len(filtered) == 0 {
			fmt.Println("No rules match the filter criteria.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "RULE ID\tSEVERITY\tCATEGORY\tNAME")
		fmt.Fprintln(w, "-------\t--------\t--------\t----")

		for _, rule := range filtered {
			status := ""
			if !rule.Enabled {
				status = " [disabled]"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s%s\n",
				rule.ID,
				strings.ToUpper(string(rule.Severity)),
				rule.Category,
				rule.Name,
				status,
			)
		}
		if err := w.Flush(); err != nil {
			return err
		}

		fmt.Printf("\nTotal: %d rules\n", len(filtered))
		return nil
	},
}

var rulesShowCmd = &cobra.Command{
	Use:   "show <RULE-ID>",
	Short: "Show detailed information about a rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ruleID := rules.RuleID(strings.ToUpper(args[0]))
		rule, ok := rules.Lookup(ruleID)
		if !ok {
			return fmt.Errorf("rule %q not found", ruleID)
		}

		printRuleDetail(rule)
		return nil
	},
}

var rulesExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all rules to YAML or JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		registry := rules.Global()

		switch strings.ToLower(exportFormat) {
		case "yaml", "yml":
			return rules.ExportToYAML(registry, exportOutput)
		case "json":
			return rules.ExportToJSON(registry, exportOutput)
		default:
			return fmt.Errorf("unsupported format: %s (use yaml or json)", exportFormat)
		}
	},
}

var (
	showDisabled   bool
	filterSeverity string
	filterCategory string
	searchQuery    string
	exportFormat   string
	exportOutput   string
)

func printRuleDetail(rule *rules.Rule) {
	sep := strings.Repeat("-", 60)

	fmt.Printf("\n%s\n", sep)
	fmt.Printf("  %s\n", rule.ID)
	fmt.Printf("%s\n\n", sep)

	fmt.Printf("%-20s %s\n", "Name:", rule.Name)
	fmt.Printf("%-20s %s\n", "Severity:", strings.ToUpper(string(rule.Severity)))
	fmt.Printf("%-20s %s\n", "Confidence:", strings.ToUpper(string(rule.Confidence)))
	fmt.Printf("%-20s %s\n", "Category:", rule.Category)
	fmt.Printf("%-20s %s\n", "Language:", rule.Language)
	fmt.Printf("%-20s %s\n", "Detector:", rule.DetectorName)
	fmt.Printf("%-20s %.1f\n", "CVSS Score:", rule.CVSSScore())

	if len(rule.Tags) > 0 {
		fmt.Printf("%-20s %s\n", "Tags:", strings.Join(rule.Tags, ", "))
	}
	if len(rule.References.SWC) > 0 {
		fmt.Printf("%-20s %s\n", "SWC:", strings.Join(rule.References.SWC, ", "))
	}
	if len(rule.References.CWE) > 0 {
		fmt.Printf("%-20s %s\n", "CWE:", strings.Join(rule.References.CWE, ", "))
	}

	fmt.Printf("\n%s\n\n", rule.FullDescription)

	if rule.Remediation != "" {
		fmt.Printf("REMEDIATION:\n%s\n\n", rule.Remediation)
	}
	if rule.Examples.Vulnerable != "" {
		fmt.Printf("VULNERABLE EXAMPLE:\n```solidity\n%s\n```\n\n", rule.Examples.Vulnerable)
	}
	if rule.Examples.Safe != "" {
		fmt.Printf("SAFE EXAMPLE:\n```solidity\n%s\n```\n\n", rule.Examples.Safe)
	}
	if len(rule.References.URLs) > 0 {
		fmt.Println("REFERENCES:")
		for _, url := range rule.References.URLs {
			fmt.Printf("  - %s\n", url)
		}
		fmt.Println()
	}
}

func init() {
	rulesListCmd.Flags().BoolVar(&showDisabled, "all", false, "Show disabled rules")
	rulesListCmd.Flags().StringVar(&filterSeverity, "severity", "", "Filter by severity (critical/high/medium/low/informational)")
	rulesListCmd.Flags().StringVar(&filterCategory, "category", "", "Filter by category")
	rulesListCmd.Flags().StringVarP(&searchQuery, "search", "s", "", "Search in rule ID, name, and description")

	rulesExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "yaml", "Export format: yaml, json")
	rulesExportCmd.Flags().StringVarP(&exportOutput, "output", "o", "solsec-rules.yaml", "Output file path")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesShowCmd)
	rulesCmd.AddCommand(rulesExportCmd)
	rootCmd.AddCommand(rulesCmd)
}

package rules_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/rules"
)

func TestDefaultRegistry_AllRulesHaveRequiredFields(t *testing.T) {
	r := rules.DefaultRegistry()

	for _, rule := range r.All() {
		t.Run(string(rule.ID), func(t *testing.T) {
			if rule.ID == "" {
				t.Error("ID must not be empty")
			}
			if rule.Name == "" {
				t.Errorf("[%s] Name must not be empty", rule.ID)
			}
			if rule.ShortDescription == "" {
				t.Errorf("[%s] ShortDescription must not be empty", rule.ID)
			}
			if rule.FullDescription == "" {
				t.Errorf("[%s] FullDescription must not be empty", rule.ID)
			}
			if rule.Severity == "" {
				t.Errorf("[%s] Severity must not be empty", rule.ID)
			}
			if rule.Confidence == "" {
				t.Errorf("[%s] Confidence must not be empty", rule.ID)
			}
			if rule.Category == "" {
				t.Errorf("[%s] Category must not be empty", rule.ID)
			}
			if rule.Remediation == "" {
				t.Errorf("[%s] Remediation must not be empty", rule.ID)
			}
			if rule.DetectorName == "" {
				t.Errorf("[%s] DetectorName must not be empty", rule.ID)
			}
		})
	}
}

func TestDefaultRegistry_IDFormatIsValid(t *testing.T) {
	r := rules.DefaultRegistry()

	for _, rule := range r.All() {
		id := string(rule.ID)

		if !strings.HasPrefix(id, "SOLSEC-") {
			t.Errorf("rule %s: ID must start with SOLSEC-", id)
		}

		parts := strings.Split(id, "-")
		if len(parts) != 3 {
			t.Errorf("rule %s: ID must have format SOLSEC-CATEGORY-NNN", id)
			continue
		}

		num := parts[2]
		if len(num) != 3 {
			t.Errorf("rule %s: numeric suffix must be 3 digits, got %q", id, num)
		}
		for _, ch := range num {
			if ch < '0' || ch > '9' {
				t.Errorf("rule %s: numeric suffix must be digits, got %q", id, num)
				break
			}
		}
	}
}

func TestDefaultRegistry_NoDuplicateIDs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("duplicate rule ID detected: %v", r)
		}
	}()
	rules.DefaultRegistry()
}

func TestDefaultRegistry_AllEnabledByDefault(t *testing.T) {
	r := rules.DefaultRegistry()
	all := r.All()

	if len(all) == 0 {
		t.Fatal("no rules registered")
	}

	for _, rule := range all {
		if rule.ID == rules.IDInit005 {
			if rule.Enabled {
				t.Errorf("%s should be disabled by default", rule.ID)
			}
			continue
		}
		if !rule.Enabled {
			t.Errorf("%s should be enabled by default", rule.ID)
		}
	}
}

func TestRegistry_ByDetector(t *testing.T) {
	r := rules.DefaultRegistry()
	reentrancyRules := r.ByDetector("reentrancy")

	if len(reentrancyRules) == 0 {
		t.Error("expected at least one rule for 'reentrancy' detector")
	}

	for _, rule := range reentrancyRules {
		if rule.DetectorName != "reentrancy" {
			t.Errorf("rule %s has wrong detector: %s", rule.ID, rule.DetectorName)
		}
	}
}

func TestRegistry_ByCategory(t *testing.T) {
	r := rules.DefaultRegistry()
	reentrancyRules := r.ByCategory(rules.CategoryReentrancy)

	if len(reentrancyRules) == 0 {
		t.Error("expected reentrancy rules")
	}

	for _, rule := range reentrancyRules {
		if rule.Category != rules.CategoryReentrancy {
			t.Errorf("rule %s in wrong category", rule.ID)
		}
	}
}

func TestRegistry_Filter_BySeverity(t *testing.T) {
	r := rules.DefaultRegistry()
	critical := r.Filter(rules.FilterOptions{
		Severities: []rules.Severity{rules.SeverityCritical},
	})

	for _, rule := range critical {
		if rule.Severity != rules.SeverityCritical {
			t.Errorf("filter returned non-critical rule: %s (%s)",
				rule.ID, rule.Severity)
		}
	}
}

func TestRegistry_Filter_ByTag(t *testing.T) {
	r := rules.DefaultRegistry()
	tagged := r.Filter(rules.FilterOptions{
		Tags: []string{"reentrancy"},
	})

	if len(tagged) == 0 {
		t.Error("expected rules with 'reentrancy' tag")
	}

	for _, rule := range tagged {
		found := false
		for _, tag := range rule.Tags {
			if strings.EqualFold(tag, "reentrancy") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %s returned for 'reentrancy' tag but doesn't have it", rule.ID)
		}
	}
}

func TestRegistry_Filter_BySearchQuery(t *testing.T) {
	r := rules.DefaultRegistry()
	results := r.Filter(rules.FilterOptions{
		SearchQuery: "delegatecall",
	})

	if len(results) == 0 {
		t.Error("expected results for search query 'delegatecall'")
	}
}

func TestRule_CVSSScore(t *testing.T) {
	cases := []struct {
		severity rules.Severity
		min, max float64
	}{
		{rules.SeverityCritical, 9.0, 10.0},
		{rules.SeverityHigh, 7.0, 9.0},
		{rules.SeverityMedium, 4.0, 7.0},
		{rules.SeverityLow, 0.0, 4.0},
	}

	for _, tc := range cases {
		rule := &rules.Rule{Severity: tc.severity}
		score := rule.CVSSScore()
		if score < tc.min || score > tc.max {
			t.Errorf("CVSS for %s = %.1f, want %.1f-%.1f",
				tc.severity, score, tc.min, tc.max)
		}
	}
}

func TestRule_SARIFLevel(t *testing.T) {
	cases := []struct {
		severity rules.Severity
		want     string
	}{
		{rules.SeverityCritical, "error"},
		{rules.SeverityHigh, "error"},
		{rules.SeverityMedium, "warning"},
		{rules.SeverityLow, "note"},
		{rules.SeverityInformational, "note"},
	}

	for _, tc := range cases {
		rule := &rules.Rule{Severity: tc.severity}
		got := rule.SARIFLevel()
		if got != tc.want {
			t.Errorf("SARIFLevel(%s) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestGlobal_IsSingleton(t *testing.T) {
	r1 := rules.Global()
	r2 := rules.Global()
	if r1 != r2 {
		t.Error("Global() should return the same instance")
	}
}

func TestLookup_ExistingRule(t *testing.T) {
	rule, ok := rules.Lookup(rules.IDReentrancy001)
	if !ok {
		t.Fatal("IDReentrancy001 should exist in global registry")
	}
	if rule.ID != rules.IDReentrancy001 {
		t.Errorf("wrong rule returned: %s", rule.ID)
	}
}

func TestLookup_NonExistingRule(t *testing.T) {
	_, ok := rules.Lookup("SOLSEC-NONEXISTENT-999")
	if ok {
		t.Error("non-existing rule should return false")
	}
}

func TestAllRulesHaveSWCOrCWE(t *testing.T) {
	r := rules.DefaultRegistry()
	for _, rule := range r.All() {
		if rule.Severity != rules.SeverityCritical && rule.Severity != rules.SeverityHigh {
			continue
		}
		hasSWC := len(rule.References.SWC) > 0
		hasCWE := len(rule.References.CWE) > 0
		if !hasSWC && !hasCWE {
			t.Errorf("[%s] Critical/High rule must have SWC or CWE reference", rule.ID)
		}
	}
}

func TestExamplesForCriticalRules(t *testing.T) {
	r := rules.DefaultRegistry()
	for _, rule := range r.All() {
		if rule.Severity != rules.SeverityCritical {
			continue
		}
		if rule.Examples.Vulnerable == "" {
			t.Errorf("[%s] Critical rule should have a vulnerable code example", rule.ID)
		}
		if rule.Examples.Safe == "" {
			t.Errorf("[%s] Critical rule should have a safe code example", rule.ID)
		}
	}
}

package rules

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Registry struct {
	mu    sync.RWMutex
	rules map[RuleID]*Rule

	// Bir detector birden fazla kural tetikleyebilir
	detectorIndex map[string][]RuleID

	categoryIndex map[Category][]RuleID
}

func NewRegistry() *Registry {
	return &Registry{
		rules:         make(map[RuleID]*Rule),
		detectorIndex: make(map[string][]RuleID),
		categoryIndex: make(map[Category][]RuleID),
	}
}

func (r *Registry) Register(rule *Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.rules[rule.ID]; exists {
		panic(fmt.Sprintf("rule ID conflict: %s already registered", rule.ID))
	}

	r.rules[rule.ID] = rule
	r.detectorIndex[rule.DetectorName] = append(r.detectorIndex[rule.DetectorName], rule.ID)
	r.categoryIndex[rule.Category] = append(r.categoryIndex[rule.Category], rule.ID)
}

func (r *Registry) Get(id RuleID) (*Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	return rule, ok
}

func (r *Registry) MustGet(id RuleID) *Rule {
	rule, ok := r.Get(id)
	if !ok {
		panic(fmt.Sprintf("rule not found: %s", id))
	}
	return rule
}

func (r *Registry) ByDetector(detectorName string) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := r.detectorIndex[detectorName]
	rules := make([]*Rule, 0, len(ids))
	for _, id := range ids {
		if rule, ok := r.rules[id]; ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (r *Registry) ByCategory(cat Category) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := r.categoryIndex[cat]
	rules := make([]*Rule, 0, len(ids))
	for _, id := range ids {
		if rule, ok := r.rules[id]; ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (r *Registry) All() []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]*Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})
	return rules
}

func (r *Registry) Enabled() []*Rule {
	all := r.All()
	enabled := make([]*Rule, 0, len(all))
	for _, rule := range all {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

func (r *Registry) Filter(opts FilterOptions) []*Rule {
	all := r.All()
	var result []*Rule

	for _, rule := range all {
		if !rule.Enabled && !opts.IncludeDisabled {
			continue
		}
		if len(opts.Categories) > 0 && !containsCategory(opts.Categories, rule.Category) {
			continue
		}
		if len(opts.Severities) > 0 && !containsSeverity(opts.Severities, rule.Severity) {
			continue
		}
		if len(opts.Tags) > 0 && !hasAnyTag(rule.Tags, opts.Tags) {
			continue
		}
		if opts.Language != "" && rule.Language != opts.Language && rule.Language != LanguageBoth {
			continue
		}
		if opts.SearchQuery != "" {
			q := strings.ToLower(opts.SearchQuery)
			if !strings.Contains(strings.ToLower(string(rule.ID)), q) &&
				!strings.Contains(strings.ToLower(rule.Name), q) &&
				!strings.Contains(strings.ToLower(rule.ShortDescription), q) {
				continue
			}
		}
		result = append(result, rule)
	}
	return result
}

type FilterOptions struct {
	Categories      []Category
	Severities      []Severity
	Tags            []string
	Language        Language
	SearchQuery     string
	IncludeDisabled bool
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

func containsCategory(cats []Category, c Category) bool {
	for _, cat := range cats {
		if cat == c {
			return true
		}
	}
	return false
}

func containsSeverity(sevs []Severity, s Severity) bool {
	for _, sev := range sevs {
		if sev == s {
			return true
		}
	}
	return false
}

func hasAnyTag(ruleTags []string, filterTags []string) bool {
	for _, rt := range ruleTags {
		for _, ft := range filterTags {
			if strings.EqualFold(rt, ft) {
				return true
			}
		}
	}
	return false
}

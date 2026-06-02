package rules

import "sync"

var (
	globalOnce sync.Once
	globalReg  *Registry
)

func Global() *Registry {
	globalOnce.Do(func() {
		globalReg = DefaultRegistry()
	})
	return globalReg
}

func Lookup(id RuleID) (*Rule, bool) {
	return Global().Get(id)
}

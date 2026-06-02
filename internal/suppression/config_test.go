package suppression_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/config"
	"github.com/ayb-blc/solsec/internal/rules"
	"github.com/ayb-blc/solsec/internal/suppression"
)

func testConfig(entries []config.IgnoreEntry) *config.Config {
	cfg := config.Default()
	cfg.Ignore = entries
	return cfg
}

func TestConfigSuppression_ExactFile(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule: string(rules.IDReentrancy001),
			File: "contracts/LegacyVault.sol",
		},
	})

	cs, warnings := suppression.NewConfigSuppression(cfg)
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	if !cs.IsSuppressed(rules.IDReentrancy001, "contracts/LegacyVault.sol", "") {
		t.Error("should be suppressed for exact file match")
	}
	if cs.IsSuppressed(rules.IDReentrancy001, "contracts/NewVault.sol", "") {
		t.Error("should NOT be suppressed for different file")
	}
}

func TestConfigSuppression_GlobPattern(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule: string(rules.IDAccessControl001),
			File: "test/**",
		},
	})

	cs, _ := suppression.NewConfigSuppression(cfg)

	cases := []struct {
		file       string
		suppressed bool
	}{
		{"test/Vault.t.sol", true},
		{"test/mocks/MockToken.sol", true},
		{"contracts/Vault.sol", false},
		{"src/Vault.sol", false},
	}

	for _, tc := range cases {
		got := cs.IsSuppressed(rules.IDAccessControl001, tc.file, "")
		if got != tc.suppressed {
			t.Errorf("IsSuppressed(%q) = %v, want %v", tc.file, got, tc.suppressed)
		}
	}
}

func TestConfigSuppression_FunctionLevel(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule:     string(rules.IDReentrancy001),
			File:     "contracts/Vault.sol",
			Function: "withdraw",
		},
	})

	cs, _ := suppression.NewConfigSuppression(cfg)

	if !cs.IsSuppressed(rules.IDReentrancy001, "contracts/Vault.sol", "withdraw") {
		t.Error("should be suppressed for matching function")
	}
	if cs.IsSuppressed(rules.IDReentrancy001, "contracts/Vault.sol", "deposit") {
		t.Error("should NOT be suppressed for different function")
	}
}

func TestConfigSuppression_GlobalRule(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule: string(rules.IDIntegerOverflow002),
		},
	})

	cs, _ := suppression.NewConfigSuppression(cfg)

	if !cs.IsSuppressed(rules.IDIntegerOverflow002, "contracts/Vault.sol", "") {
		t.Error("global rule should suppress in any file")
	}
	if !cs.IsSuppressed(rules.IDIntegerOverflow002, "src/Token.sol", "") {
		t.Error("global rule should suppress in any file")
	}
}

func TestConfigSuppression_ExpiredEntry(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule:   string(rules.IDReentrancy001),
			File:   "contracts/Vault.sol",
			Expiry: "2020-01-01",
		},
	})

	cs, warnings := suppression.NewConfigSuppression(cfg)

	if len(warnings) == 0 {
		t.Error("expected warning for expired suppression")
	}

	if cs.IsSuppressed(rules.IDReentrancy001, "contracts/Vault.sol", "") {
		t.Error("expired suppression should not suppress")
	}
}

func TestConfigSuppression_FutureExpiry(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule:   string(rules.IDReentrancy001),
			File:   "contracts/Vault.sol",
			Expiry: "2099-12-31", // Gelecek tarih
		},
	})

	cs, warnings := suppression.NewConfigSuppression(cfg)

	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if !cs.IsSuppressed(rules.IDReentrancy001, "contracts/Vault.sol", "") {
		t.Error("future expiry should still suppress")
	}
}

func TestConfigSuppression_InvalidExpiryFormat(t *testing.T) {
	cfg := testConfig([]config.IgnoreEntry{
		{
			Rule:   string(rules.IDReentrancy001),
			Expiry: "31/12/2025",
		},
	})

	_, warnings := suppression.NewConfigSuppression(cfg)
	if len(warnings) == 0 {
		t.Error("invalid date format should produce a warning")
	}
}

package fingerprint_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/fingerprint"
	"github.com/ayb-blc/solsec/internal/rules"
)

func sampleFinding() analyzer.Finding {
	return analyzer.Finding{
		RuleID:       rules.IDReentrancy001,
		DetectorName: "reentrancy",
		Title:        "Potential reentrancy in function 'withdraw'",
		Description:  "External call before state update.",
		Filepath:     "/home/user/myproject/contracts/Vault.sol",
		Line:         42,
		CodeSnippet:  "  (bool ok,) = msg.sender.call{value: amount}(\"\");",
		Severity:     analyzer.Critical,
		Confidence:   analyzer.ConfidenceHigh,
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	f := sampleFinding()
	fp1 := fingerprint.Compute(f, "/home/user/myproject")
	fp2 := fingerprint.Compute(f, "/home/user/myproject")

	if fp1.ID != fp2.ID {
		t.Errorf("fingerprint not deterministic:\n  run1: %s\n  run2: %s",
			fp1.ID, fp2.ID)
	}
}

func TestFingerprint_Format(t *testing.T) {
	f := sampleFinding()
	fp := fingerprint.Compute(f, "/home/user/myproject")

	if len(fp.ID) < 15 {
		t.Errorf("fingerprint too short: %q", fp.ID)
	}
	if fp.ID[:7] != "SOLSEC-" {
		t.Errorf("fingerprint should start with SOLSEC-: %q", fp.ID)
	}
}

func TestFingerprint_StableAcrossLineChanges(t *testing.T) {
	f1 := sampleFinding()
	f1.Line = 42

	f2 := sampleFinding()
	f2.Line = 85

	fp1 := fingerprint.Compute(f1, "/project")
	fp2 := fingerprint.Compute(f2, "/project")

	if fp1.ID != fp2.ID {
		t.Errorf("fingerprint changed with line number:\n  line 42: %s\n  line 85: %s",
			fp1.ID, fp2.ID)
	}
}

func TestFingerprint_DifferentForDifferentRules(t *testing.T) {
	f1 := sampleFinding()
	f1.RuleID = rules.IDReentrancy001

	f2 := sampleFinding()
	f2.RuleID = rules.IDTxOrigin001

	fp1 := fingerprint.Compute(f1, "/project")
	fp2 := fingerprint.Compute(f2, "/project")

	if fp1.ID == fp2.ID {
		t.Error("different rules should produce different fingerprints")
	}
}

func TestFingerprint_DifferentForDifferentFiles(t *testing.T) {
	f1 := sampleFinding()
	f1.Filepath = "/project/contracts/Vault.sol"

	f2 := sampleFinding()
	f2.Filepath = "/project/contracts/Token.sol"

	fp1 := fingerprint.Compute(f1, "/project")
	fp2 := fingerprint.Compute(f2, "/project")

	if fp1.ID == fp2.ID {
		t.Error("different files should produce different fingerprints")
	}
}

func TestFingerprint_StableWithWhitespaceChange(t *testing.T) {
	f1 := sampleFinding()
	f1.CodeSnippet = "(bool ok,) = msg.sender.call{value: amount}(\"\");"

	f2 := sampleFinding()
	f2.CodeSnippet = "  (bool ok,)  =  msg.sender.call{value: amount}(\"\");  "

	fp1 := fingerprint.Compute(f1, "/project")
	fp2 := fingerprint.Compute(f2, "/project")

	if fp1.ID != fp2.ID {
		t.Errorf("whitespace change should not affect fingerprint:\n  %s\n  %s",
			fp1.ID, fp2.ID)
	}
}

func TestFingerprint_StableWithCommentChange(t *testing.T) {
	f1 := sampleFinding()
	f1.CodeSnippet = "(bool ok,) = addr.call(\"\"); // transfer ETH"

	f2 := sampleFinding()
	f2.CodeSnippet = "(bool ok,) = addr.call(\"\"); // fixed comment"

	fp1 := fingerprint.Compute(f1, "/project")
	fp2 := fingerprint.Compute(f2, "/project")

	if fp1.ID != fp2.ID {
		t.Errorf("comment change should not affect fingerprint:\n  %s\n  %s",
			fp1.ID, fp2.ID)
	}
}

func TestFingerprint_PathNormalization(t *testing.T) {
	f1 := sampleFinding()
	f1.Filepath = "/home/alice/project/contracts/Vault.sol"

	f2 := sampleFinding()
	f2.Filepath = "/home/bob/project/contracts/Vault.sol"

	fp1 := fingerprint.Compute(f1, "/home/alice/project")
	fp2 := fingerprint.Compute(f2, "/home/bob/project")

	if fp1.ID != fp2.ID {
		t.Errorf("different developer paths should produce same fingerprint:\n  %s\n  %s",
			fp1.ID, fp2.ID)
	}
}

func TestComputeAll_UpdatesFindings(t *testing.T) {
	findings := []analyzer.Finding{sampleFinding(), sampleFinding()}
	findings[1].RuleID = rules.IDTxOrigin001

	fingerprint.ComputeAll(findings, "/project")

	for i, f := range findings {
		if f.FingerprintID == "" {
			t.Errorf("finding[%d] has empty FingerprintID", i)
		}
	}

	if findings[0].FingerprintID == findings[1].FingerprintID {
		t.Error("different findings should have different fingerprints")
	}
}

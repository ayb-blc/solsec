package detectors_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

func TestTxOriginDetector(t *testing.T) {
	d := detectors.NewTxOriginDetector()

	cases := []DetectorTestCase{
		// True positives
		{
			Name:             "require tx.origin == owner",
			ContractFile:     "vulnerable/tx_origin/auth_bypass.sol",
			ExpectedFindings: 2,
			ExpectedSeverity: analyzer.High,
		},
		{
			Name:             "if tx.origin check",
			ContractFile:     "vulnerable/tx_origin/if_check.sol",
			ExpectedFindings: 1,
		},

		{
			Name:             "tx.origin == msg.sender EOA check",
			ContractFile:     "safe/tx_origin/eoa_check.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "tx.origin in comment",
			ContractFile:     "safe/tx_origin/in_comment.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "tx.origin for logging only",
			ContractFile:     "safe/tx_origin/logging_only.sol",
			ExpectedFindings: 0,
		},
	}

	RunDetectorTests(t, d, cases)
}

// internal/detectors/signature_replay_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestSignatureReplay_Fixtures(t *testing.T) {
	d := detectors.NewSignatureReplayDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/signature_replay/*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(findings) != fixture.ExpectedFindings {
				t.Fatalf("findings = %d, want %d: %#v", len(findings), fixture.ExpectedFindings, findings)
			}
		})
	}
}

func TestSignatureReplay_Critical_NoNonceNoChainId(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function permit(address owner, address spender, uint256 value,
                    uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(owner, spender, value));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("no nonce, no chainId = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestSignatureReplay_High_HasChainIdNoNonce(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function permit(address owner, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(owner, value, block.chainid));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("no nonce = HIGH expected")
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestSignatureReplay_Medium_HasNonceNoChainId(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) public nonces;
    function permit(address owner, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(owner, value, nonces[owner]++));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("no chainId = MEDIUM expected")
	}
	if findings[0].Severity != analyzer.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestSignatureReplay_Safe_EIP712(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) public nonces;
    function permit(address owner, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, owner, value, nonces[owner]++, deadline));
        address signer = ECDSA.recover(_hashTypedDataV4(structHash), v, r, s);
        require(signer == owner);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("EIP-712 with nonce+deadline = safe, got %d findings", len(findings))
	}
}

func TestSignatureReplay_Safe_DomainSeparator(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    function permit(address owner, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline);
        bytes32 hash = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(owner, value, nonces[owner]++, deadline))
        ));
        require(ecrecover(hash, v, r, s) == owner);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("DOMAIN_SEPARATOR = safe, got %d findings", len(findings))
	}
}

func TestSignatureReplay_Safe_InternalHelper(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    // Internal helper; skip.
    function recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("internal helper = skip, got %d findings", len(findings))
	}
}

func TestSignatureReplay_Safe_UseNonce(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function execute(address target, bytes calldata data,
                     uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, target, keccak256(data), _useNonce(msg.sender), deadline)
        );
        require(ecrecover(_hashTypedDataV4(structHash), v, r, s) == msg.sender);
        target.call(data);
    }
}`
	d := detectors.NewSignatureReplayDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("_useNonce + _hashTypedDataV4 = safe, got %d findings", len(findings))
	}
}

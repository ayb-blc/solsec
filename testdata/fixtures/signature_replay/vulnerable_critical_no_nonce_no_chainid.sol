// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/vulnerable_critical_no_nonce_no_chainid.sol

// FIXTURE: signature_replay/vulnerable_critical_no_nonce_no_chainid
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-003
// SEVERITY: critical
// PATTERN: ecrecover with no nonce, no chainId
pragma solidity ^0.8.0;

contract VulnerablePermit {
    mapping(address => mapping(address => uint256)) public allowance;

    // VULNERABLE: same signature can be replayed on any chain, infinitely
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(owner, spender, value));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "invalid sig");
        allowance[owner][spender] = value;
    }
}

// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/vulnerable_medium_no_chainid.sol

// FIXTURE: signature_replay/vulnerable_medium_no_chainid
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-003
// SEVERITY: medium
// PATTERN: has nonce but no chainId - cross-chain replay
pragma solidity ^0.8.0;

contract CrossChainVulnerable {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    // MEDIUM: nonce present but no chainId means cross-chain replay.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 hash = keccak256(
            abi.encodePacked(owner, spender, value, nonces[owner]++)
        );
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "invalid sig");
        allowance[owner][spender] = value;
    }
}

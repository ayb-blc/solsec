// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/vulnerable_high_no_nonce.sol

// FIXTURE: signature_replay/vulnerable_high_no_nonce
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-003
// SEVERITY: high
// PATTERN: has chainId but no nonce - same-chain replay
pragma solidity ^0.8.0;

contract SemiProtected {
    mapping(address => mapping(address => uint256)) public allowance;

    // HIGH: chainId present, but no nonce means same-chain replay.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 hash = keccak256(
            abi.encodePacked(owner, spender, value, block.chainid)
        );
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "invalid sig");
        allowance[owner][spender] = value;
    }
}

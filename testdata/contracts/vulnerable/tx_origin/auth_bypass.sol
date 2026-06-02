// testdata/contracts/vulnerable/tx_origin/auth_bypass.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: tx-origin
// EXPECTED_FINDINGS: 2
// SEVERITY: HIGH
// PATTERN: tx.origin used for access control in multiple functions
contract TxOriginAuthBypass {
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin authentication
    // If the owner is tricked into calling a malicious contract:
    // tx.origin == owner passes because tx.origin is still the victim EOA.
    // msg.sender would be the malicious contract, but this check does not use it.
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner"); // FINDING #1
        owner = newOwner;
    }

    function emergencyPause() external {
        require(tx.origin == owner, "Not owner"); // FINDING #2
        paused = true;
    }

    // SAFE: tx.origin == msg.sender is an EOA-only check, not owner auth.
    // The detector should not report this line.
    function onlyEOA() external view {
        require(tx.origin == msg.sender, "No contracts allowed");
        // ... some logic
    }
}

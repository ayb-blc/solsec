// testdata/contracts/vulnerable/tx_origin/auth_bypass.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: tx-origin
// EXPECTED_FINDINGS: 2
// SEVERITY: HIGH
// PATTERN: tx.origin used for access control in multiple functions
contract TxOriginAuthBypass {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin authentication
    // If the attacker calls through PhishingContract:
    // tx.origin == owner (victim) passes
    // msg.sender == PhishingContract would be caught by a safe check, but no such check exists
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner"); // FINDING #1
        owner = newOwner;
    }

    function withdraw() external {
        require(tx.origin == owner, "Not owner"); // FINDING #2
        payable(owner).transfer(address(this).balance);
    }

    // SAFE: tx.origin == msg.sender is an EOA check and can be legitimate
    // The tool should not report this pattern
    function onlyEOA() external {
        require(tx.origin == msg.sender, "No contracts allowed");
        // ... some logic
    }
}

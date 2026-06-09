// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/vulnerable_provider_critical.sol

// FIXTURE: flash_loan/vulnerable_provider_critical
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-001
// SEVERITY: critical
// PATTERN: state write before callback, no nonReentrant
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(address initiator, uint256 amount, bytes calldata data) external;
}

contract VulnerablePool {
    mapping(address => uint256) public balances;
    uint256 public totalBorrowed;

    // VULNERABLE: totalBorrowed written before callback, no guard
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        totalBorrowed += amount;                                         // state write
        IFlashBorrower(receiver).onFlashLoan(msg.sender, amount, data); // callback
        require(totalBorrowed == 0, "not repaid");
        totalBorrowed -= amount;                                         // state write
    }
}

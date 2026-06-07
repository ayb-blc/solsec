// SPDX-License-Identifier: MIT

// FIXTURE: init/vulnerable_high
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-001
// SEVERITY: high
// PATTERN: no initializer modifier + state write (non-critical)
pragma solidity ^0.8.0;

contract VaultHigh {
    uint256 public fee;
    uint256 public maxDeposit;

    // VULNERABLE: no guard, writes state, but does not touch privileged state
    function initialize(uint256 fee_, uint256 maxDeposit_) public {
        fee = fee_;
        maxDeposit = maxDeposit_;
    }
}

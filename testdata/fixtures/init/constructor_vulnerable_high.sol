// SPDX-License-Identifier: MIT

// FIXTURE: init/constructor_vulnerable_high
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-002
// SEVERITY: high
// PATTERN: upgradeable constructor writes non-critical state
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

contract HighConstructor is Initializable {
    uint256 public fee;
    uint256 public maxDeposit;

    constructor(uint256 fee_, uint256 maxDeposit_) {
        fee = fee_;
        maxDeposit = maxDeposit_;
    }

    function initialize() external initializer {}
}

// SPDX-License-Identifier: MIT

// FIXTURE: override/vulnerable_drops_onlyowner
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-005
// SEVERITY: critical
// PATTERN: child override drops onlyOwner and writes state
pragma solidity ^0.8.0;

contract BaseFeeController {
    uint256 public fee;

    modifier onlyOwner() {
        _;
    }

    function setFee(uint256 newFee) external virtual onlyOwner {
        fee = newFee;
    }
}

contract ChildFeeController is BaseFeeController {
    function setFee(uint256 newFee) external override {
        fee = newFee;
    }
}

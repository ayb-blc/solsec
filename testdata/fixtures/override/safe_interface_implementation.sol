// SPDX-License-Identifier: MIT

// FIXTURE: override/safe_interface_implementation
// EXPECTED_FINDINGS: 0
// PATTERN: interface implementation has no modifier to drop
pragma solidity ^0.8.0;

interface IFeeController {
    function setFee(uint256 newFee) external;
}

contract FeeController is IFeeController {
    uint256 public fee;

    function setFee(uint256 newFee) external override {
        fee = newFee;
    }
}

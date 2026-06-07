// SPDX-License-Identifier: MIT

// FIXTURE: override/safe_keeps_modifier
// EXPECTED_FINDINGS: 0
// PATTERN: child preserves equivalent restriction
pragma solidity ^0.8.0;

contract BaseRestricted {
    uint256 public fee;

    modifier onlyOwner() {
        _;
    }

    function setFee(uint256 newFee) external virtual onlyOwner {
        fee = newFee;
    }
}

contract ChildRestricted is BaseRestricted {
    function setFee(uint256 newFee) external override onlyOwner {
        fee = newFee;
    }
}

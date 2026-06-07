// SPDX-License-Identifier: MIT

// FIXTURE: override/safe_different_modifier_same_class
// EXPECTED_FINDINGS: 0
// PATTERN: child uses different but still restrictive modifier
pragma solidity ^0.8.0;

contract BaseOwnerRestricted {
    uint256 public fee;

    modifier onlyOwner() {
        _;
    }

    function setFee(uint256 newFee) external virtual onlyOwner {
        fee = newFee;
    }
}

contract ChildAdminRestricted is BaseOwnerRestricted {
    modifier onlyAdmin() {
        _;
    }

    function setFee(uint256 newFee) external override onlyAdmin {
        fee = newFee;
    }
}

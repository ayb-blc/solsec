// SPDX-License-Identifier: MIT

// FIXTURE: init/constructor_safe_not_upgradeable
// EXPECTED_FINDINGS: 0
// PATTERN: regular non-upgradeable contract can initialize state in constructor
pragma solidity ^0.8.0;

contract RegularVault {
    address public owner;
    uint256 public fee;

    constructor(address owner_, uint256 fee_) {
        owner = owner_;
        fee = fee_;
    }
}

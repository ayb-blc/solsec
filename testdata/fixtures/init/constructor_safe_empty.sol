// SPDX-License-Identifier: MIT

// FIXTURE: init/constructor_safe_empty
// EXPECTED_FINDINGS: 0
// PATTERN: upgradeable contract has an empty constructor
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

contract EmptyConstructorUpgradeable is Initializable {
    uint256 public fee;

    constructor() {}

    function initialize(uint256 fee_) external initializer {
        fee = fee_;
    }
}

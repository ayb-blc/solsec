// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_safe_constants_only
// EXPECTED_FINDINGS: 0
// PATTERN: only constant/immutable variables
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract ConstantBase is Initializable {
    uint256 public constant VERSION = 1;
    address public immutable FACTORY;         

    constructor(address factory_) {
        FACTORY = factory_;
    }

    function initialize() external initializer {}
}

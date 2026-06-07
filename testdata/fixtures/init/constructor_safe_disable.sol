// SPDX-License-Identifier: MIT

// FIXTURE: init/constructor_safe_disable
// EXPECTED_FINDINGS: 0
// PATTERN: upgradeable implementation hardens itself with _disableInitializers()
pragma solidity ^0.8.0;

contract Initializable {
    function _disableInitializers() internal {}
    modifier initializer() {
        _;
    }
}

contract SafeDisable is Initializable {
    address public owner;

    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        owner = owner_;
    }
}

// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_safe_init_called
// EXPECTED_FINDINGS: 0
// PATTERN: OwnableUpgradeable initialized directly
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract OwnableUpgradeable {
    address private _owner;
    uint256[49] private __gap;

    function __Ownable_init() internal {
        _owner = msg.sender;
    }
}

contract VaultOwnableSafe is Initializable, OwnableUpgradeable {
    function initialize() external initializer {
        __Ownable_init();
    }
}

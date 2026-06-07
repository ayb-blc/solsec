// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_safe_multiline_inherit
// EXPECTED_FINDINGS: 0
// PATTERN: multiline inheritance with Ownable initialization
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract PausableUpgradeable {}

abstract contract OwnableUpgradeable {
    address private _owner;
    uint256[49] private __gap;

    function __Ownable_init_unchained() internal {
        _owner = msg.sender;
    }
}

contract MultilineVault is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable
{
    function initialize() external initializer {
        __Ownable_init_unchained();
    }
}

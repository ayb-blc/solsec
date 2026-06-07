// SPDX-License-Identifier: MIT

// FIXTURE: init/safe_initializer_modifier
// EXPECTED_FINDINGS: 0
// PATTERN: protected by OZ initializer modifier
pragma solidity ^0.8.0;

interface IERC20 {}

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract OwnableUpgradeable {
    address private _owner;

    function __Ownable_init() internal {}

    function _transferOwnership(address owner_) internal {
        _owner = owner_;
    }
}

contract VaultSafe is Initializable, OwnableUpgradeable {
    IERC20 public token;

    function initialize(address token_, address owner_) external initializer {
        __Ownable_init();
        _transferOwnership(owner_);
        token = IERC20(token_);
    }
}

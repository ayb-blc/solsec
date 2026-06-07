// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_safe_transfer_ownership
// EXPECTED_FINDINGS: 0
// PATTERN: initialize transfers ownership explicitly
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract OwnableUpgradeable {
    address private _owner;
    uint256[49] private __gap;

    function _transferOwnership(address newOwner) internal {
        _owner = newOwner;
    }
}

contract TransferOwnershipVault is Initializable, OwnableUpgradeable {
    function initialize(address owner_) external initializer {
        _transferOwnership(owner_);
    }
}

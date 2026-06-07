// SPDX-License-Identifier: MIT

// FIXTURE: init/safe_manual_flag
// EXPECTED_FINDINGS: 0
// PATTERN: protected by manual initialized flag
pragma solidity ^0.8.0;

contract VaultManual {
    bool private _initialized;
    address public owner;

    function initialize(address owner_) external {
        require(!_initialized, "Already initialized");
        _initialized = true;
        owner = owner_;
    }
}

// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_safe_regular_ownable
// EXPECTED_FINDINGS: 0
// PATTERN: regular Ownable uses constructor owner setup
pragma solidity ^0.8.0;

contract Ownable {
    address private _owner;

    constructor() {
        _owner = msg.sender;
    }
}

contract RegularVault is Ownable {
    uint256 public value;
}

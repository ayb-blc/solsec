// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_safe_v5_style
// EXPECTED_FINDINGS: 0
// PATTERN: OpenZeppelin v5 style regular Ownable constructor
pragma solidity ^0.8.20;

contract Ownable {
    address private _owner;

    constructor(address initialOwner) {
        _owner = initialOwner;
    }
}

contract V5StyleVault is Ownable {
    constructor(address owner_) Ownable(owner_) {}
}

// SPDX-License-Identifier: MIT

// FIXTURE: init/safe_onlyowner_setup
// EXPECTED_FINDINGS: 0
// PATTERN: setUp protected by onlyOwner
pragma solidity ^0.8.0;

contract VaultOwnerSetup {
    address public owner;
    uint256 public fee;

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function setUp(uint256 fee_) external onlyOwner {
        fee = fee_;
    }
}

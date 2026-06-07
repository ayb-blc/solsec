// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_safe_not_upgradeable
// EXPECTED_FINDINGS: 0
// PATTERN: regular non-upgradeable contract with state variables
pragma solidity ^0.8.0;

contract RegularBase {
    uint256 public fee;
    address public owner;
}

contract RegularChild is RegularBase {
    uint256 public balance;
}

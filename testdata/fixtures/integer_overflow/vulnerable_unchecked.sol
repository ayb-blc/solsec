// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 1
contract VulnerableUnchecked {
    mapping(address => uint256) public balances;

    function add(address user, uint256 amount) external {
        unchecked {
            balances[user] += amount;
        }
    }
}

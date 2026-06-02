// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 0
contract SafePost08 {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }
}

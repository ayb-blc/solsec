// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9.0;

// EXPECTED_FINDINGS: 1
contract VulnerablePre08 {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }
}

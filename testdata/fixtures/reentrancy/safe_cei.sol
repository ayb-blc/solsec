// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FIXTURE: reentrancy/safe_cei
// EXPECTED_FINDINGS: 0
// PATTERN: correct Checks-Effects-Interactions order
contract SafeCEI {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // EFFECT first — state update before interaction
        balances[msg.sender] = 0;

        // INTERACTION last — even if attacker re-enters, balance is already 0
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
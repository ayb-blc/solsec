// testdata/contracts/safe/reentrancy/cei_correct.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: reentrancy
// EXPECTED_FINDINGS: 0
// PATTERN: correct CEI — state updated BEFORE external call
//
// CEI is applied correctly. The tool should not produce findings.
contract SafeCEI {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // EFFECT: state is updated first
        balances[msg.sender] = 0;

        // INTERACTION: external call happens after the state update
        // Even if an attacker re-enters, balances[msg.sender] is already zero
        // and cannot be withdrawn again
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

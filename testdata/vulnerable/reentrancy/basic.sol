// testdata/contracts/vulnerable/reentrancy/basic.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: reentrancy
// EXPECTED_FINDINGS: 1
// SEVERITY: CRITICAL
// PATTERN: external call before state update (classic CEI violation)
//
// This contract tests the simplest reentrancy pattern.
// The detector should produce exactly one finding for this contract.
// More or fewer findings should fail the test.
contract BasicReentrancy {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: external call (line 20) happens before state update (line 21)
    // An attacker's fallback function can re-enter this before balances is zeroed
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // SINK: external call — attacker controls receive()
        (bool success,) = msg.sender.call{value: amount}("");  // line 20
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // line 21 — too late, state updated after call
    }
}

// testdata/contracts/vulnerable/reentrancy/cross_function.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: reentrancy-inter
// EXPECTED_FINDINGS: 1
// SEVERITY: CRITICAL
// PATTERN: inter-procedural reentrancy — external call hidden in internal function
//
// This pattern tests a case that an intra-procedural detector cannot see.
// Only a call-graph-aware detector can find it.
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;
    bool private _locked;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");

        // The external call is not here; it is inside _sendFunds.
        // Intra-procedural detector: "no external call here, therefore safe" (wrong)
        // Inter-procedural detector: "_sendFunds makes an external call, therefore dangerous"
        _sendFunds(msg.sender, amount);

        // State update happens after the external call, violating CEI
        balances[msg.sender] -= amount;
    }

    // Internal function: the external call is here
    function _sendFunds(address to, uint256 amount) internal {
        (bool success,) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

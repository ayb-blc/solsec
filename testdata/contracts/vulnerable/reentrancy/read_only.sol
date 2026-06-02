// testdata/contracts/vulnerable/reentrancy/read_only.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: reentrancy-ast
// EXPECTED_FINDINGS: 1
// SEVERITY: HIGH
// PATTERN: read-only reentrancy
//
// Less common but real risk:
// State is updated (balances = 0), but an external contract can read this
// contract's state during the interaction and observe an inconsistent view.
// This can enable oracle or price manipulation.
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract ReadOnlyReentrancy {
    mapping(address => uint256) public balances;
    IPriceOracle public oracle;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        balances[msg.sender] = 0; // Effect: state updated

        // Interaction: external call. The oracle may read this contract's
        // balances during reentrancy and observe balances[msg.sender] == 0,
        // which is an inconsistent state for pricing.
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}

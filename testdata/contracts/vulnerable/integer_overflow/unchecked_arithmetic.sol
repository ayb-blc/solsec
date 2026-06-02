// testdata/contracts/vulnerable/integer_overflow/unchecked_arithmetic.sol
// SPDX-License-Identifier: MIT
// DETECTOR: integer-overflow
// EXPECTED_FINDINGS: 1
// SEVERITY: MEDIUM
pragma solidity ^0.8.0;

contract UncheckedArithmetic {
    mapping(address => uint256) public balances;

    function unsafeTransfer(address to, uint256 amount) external {
        unchecked {
            // Overflow protection is disabled; if amount > balances[msg.sender],
            // balances[msg.sender] wraps around.
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}

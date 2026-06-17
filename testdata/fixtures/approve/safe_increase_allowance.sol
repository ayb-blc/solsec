// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/safe_increase_allowance.sol

// FIXTURE: approve/safe_increase_allowance
// EXPECTED_FINDINGS: 0
// PATTERN: increaseAllowance — safe delta-based change
pragma solidity ^0.8.0;

interface IERC20 {
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
}

contract DeltaApprove {
    IERC20 public token;

    function addAllowance(address spender, uint256 additional) external {
        token.increaseAllowance(spender, additional);
    }
}

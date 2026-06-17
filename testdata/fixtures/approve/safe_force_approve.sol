// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/safe_force_approve.sol

// FIXTURE: approve/safe_force_approve
// EXPECTED_FINDINGS: 0
// PATTERN: OZ v5 forceApprove — safe, no race condition
pragma solidity ^0.8.0;

interface IERC20 {}

library SafeERC20 {
    function forceApprove(IERC20, address, uint256) internal pure {}
}

contract ModernApprove {
    using SafeERC20 for IERC20;
    IERC20 public token;

    function setupAllowance(address spender, uint256 amount) external {
        SafeERC20.forceApprove(token, spender, amount);
    }
}

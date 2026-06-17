// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/vulnerable_medium_safe_approve.sol

// FIXTURE: approve/vulnerable_medium_safe_approve
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-006
// SEVERITY: medium
// PATTERN: deprecated safeApprove()
pragma solidity ^0.8.0;

interface IERC20 {}

library SafeERC20 {
    function safeApprove(IERC20, address, uint256) internal pure {}
}

contract DeprecatedApprove {
    using SafeERC20 for IERC20;
    IERC20 public token;

    // MEDIUM: safeApprove is deprecated, use forceApprove
    function setupAllowance(address spender, uint256 amount) external {
        token.safeApprove(spender, amount);
    }
}

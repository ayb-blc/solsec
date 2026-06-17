// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/vulnerable_critical_user_controlled.sol

// FIXTURE: approve/vulnerable_critical_user_controlled
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-006
// SEVERITY: critical
// PATTERN: function parameter flows to approve() spender
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract VaultWithBadApprove {
    IERC20 public token;

    // VULNERABLE: any caller can approve themselves
    function approveTokens(address spender, uint256 amount) external {
        token.approve(spender, amount); // spender is user-controlled!
    }
}

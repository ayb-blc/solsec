// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/vulnerable_high_unlimited_no_guard.sol

// FIXTURE: approve/vulnerable_high_unlimited_no_guard
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-006
// SEVERITY: high
// PATTERN: type(uint256).max approve without access control
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract VaultUnlimited {
    IERC20 public token;
    address public router;

    // VULNERABLE: no onlyOwner, any caller can set MAX allowance
    function enableTrading() external {
        token.approve(router, type(uint256).max);
    }
}

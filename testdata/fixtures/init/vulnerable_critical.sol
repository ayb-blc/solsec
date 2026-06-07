// SPDX-License-Identifier: MIT

// FIXTURE: init/vulnerable_critical
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-001
// SEVERITY: critical
// PATTERN: no initializer modifier + privileged state write
pragma solidity ^0.8.0;

interface IERC20 {
    function mint(address to, uint256 amount) external;
}

contract VaultCritical {
    address public owner;
    address public admin;
    IERC20 public token;
    address public oracle;

    function initialize(
        address owner_,
        address admin_,
        address token_,
        address oracle_
    ) external {
        owner = owner_;
        admin = admin_;
        token = IERC20(token_);
        oracle = oracle_;
    }
}

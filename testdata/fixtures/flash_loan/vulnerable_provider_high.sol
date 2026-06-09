// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/vulnerable_provider_high.sol

// FIXTURE: flash_loan/vulnerable_provider_high
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-001
// SEVERITY: high
// PATTERN: callback to user-controlled address, no guard, no state writes
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(address initiator, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract PoolHighRisk {
    IERC20 public token;

    // HIGH: no state writes but callback still creates a reentrancy window
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(receiver, amount);
        IFlashBorrower(receiver).onFlashLoan(msg.sender, amount, data);
        require(token.balanceOf(address(this)) >= balanceBefore, "not repaid");
    }
}

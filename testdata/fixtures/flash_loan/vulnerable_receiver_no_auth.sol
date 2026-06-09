// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/vulnerable_receiver_no_auth.sol

// FIXTURE: flash_loan/vulnerable_receiver_no_auth
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-002
// SEVERITY: high
// PATTERN: onFlashLoan without msg.sender verification, performs token ops
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract VulnerableReceiver {
    address public lender;
    IERC20 public token;

    // VULNERABLE: anyone can call this directly
    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        // No require(msg.sender == lender)!
        token.approve(msg.sender, amount + fee);  // arbitrary approvals
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

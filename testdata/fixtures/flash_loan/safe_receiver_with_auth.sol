// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/safe_receiver_with_auth.sol

// FIXTURE: flash_loan/safe_receiver_with_auth
// EXPECTED_FINDINGS: 0
// PATTERN: verifies msg.sender before executing
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract SafeReceiver {
    address public lender;
    IERC20 public token;

    function onFlashLoan(
        address initiator,
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        require(msg.sender == lender, "untrusted lender");
        require(initiator == address(this), "untrusted initiator");

        token.approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/safe_provider_nonreentrant.sol

// FIXTURE: flash_loan/safe_provider_nonreentrant
// EXPECTED_FINDINGS: 0
// PATTERN: protected by nonReentrant
pragma solidity ^0.8.0;

abstract contract ReentrancyGuard {
    modifier nonReentrant() {
        _;
    }
}

interface IFlashBorrower {
    function onFlashLoan(address initiator, uint256 amount, bytes calldata data) external;
}

contract SafePool is ReentrancyGuard {
    uint256 public totalBorrowed;

    function flashLoan(address receiver, uint256 amount, bytes calldata data)
        external nonReentrant {
        totalBorrowed += amount;
        IFlashBorrower(receiver).onFlashLoan(msg.sender, amount, data);
        totalBorrowed -= amount;
    }
}

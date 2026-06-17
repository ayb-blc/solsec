// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/safe_unlimited_with_guard.sol

// FIXTURE: approve/safe_unlimited_with_guard
// EXPECTED_FINDINGS: 0
// PATTERN: unlimited approve protected by onlyOwner
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract Ownable {
    address internal owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract SafeVault is Ownable {
    IERC20 public token;
    address public immutable ROUTER;

    constructor(address router) { ROUTER = router; }

    // SAFE: onlyOwner protects the unlimited approval
    function enableTrading() external onlyOwner {
        token.approve(ROUTER, type(uint256).max);
    }
}

// SPDX-License-Identifier: MIT
// testdata/fixtures/approve/safe_constructor_approve.sol

// FIXTURE: approve/safe_constructor_approve
// EXPECTED_FINDINGS: 0
// PATTERN: unlimited approve in constructor — deployment-time, no race condition
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract DeployTimeApprove {
    IERC20 public immutable token;
    address public immutable ROUTER;

    constructor(address token_, address router_) {
        token = IERC20(token_);
        ROUTER = router_;
        // SAFE: constructor runs once at deployment, no race condition possible
        token.approve(ROUTER, type(uint256).max);
    }
}

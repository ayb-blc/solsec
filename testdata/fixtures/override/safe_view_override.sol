// SPDX-License-Identifier: MIT

// FIXTURE: override/safe_view_override
// EXPECTED_FINDINGS: 0
// PATTERN: view override does not mutate privileged state
pragma solidity ^0.8.0;

contract BaseView {
    modifier onlyOwner() {
        _;
    }

    function getSecret() external view virtual onlyOwner returns (uint256) {
        return 1;
    }
}

contract ChildView is BaseView {
    function getSecret() external view override returns (uint256) {
        return 2;
    }
}

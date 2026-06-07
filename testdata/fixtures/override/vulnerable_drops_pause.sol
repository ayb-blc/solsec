// SPDX-License-Identifier: MIT

// FIXTURE: override/vulnerable_drops_pause
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-005
// SEVERITY: critical
// PATTERN: grandparent chain preserves then drops access control
pragma solidity ^0.8.0;

contract GrandParentConfig {
    uint256 public mode;

    modifier onlyOwner() {
        _;
    }

    function configureMode(uint256 newMode) external virtual onlyOwner {
        mode = newMode;
    }
}

contract ParentConfig is GrandParentConfig {
    function configureMode(uint256 newMode) external virtual override onlyOwner {
        mode = newMode;
    }
}

contract ChildConfig is ParentConfig {
    function configureMode(uint256 newMode) external override {
        mode = newMode;
    }
}

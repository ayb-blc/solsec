// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_medium_base
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-003
// SEVERITY: medium
// PATTERN: abstract upgradeable base + state vars + no __gap
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract BaseVault is Initializable {
    uint256 public fee;        // slot 0
    address public treasury;   // slot 1
}

contract ChildVault is BaseVault {
    function initialize() external initializer {}
}

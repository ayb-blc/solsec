// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_medium_inherited
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-003
// SEVERITY: medium
// PATTERN: upgradeable base contract inherited by another contract, state vars, no gap
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

contract BaseLogic is Initializable {
    uint256 public version;

    function initialize() external initializer {}
}

contract ChildLogic is BaseLogic {
    uint256 public balance;
}

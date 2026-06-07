// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_low_leaf
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-003
// SEVERITY: low
// PATTERN: leaf upgradeable contract with state variables and no gap
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

contract LeafVault is Initializable {
    uint256 public fee;
    address public treasury;
    function initialize() external initializer {}
}

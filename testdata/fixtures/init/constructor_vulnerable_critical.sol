// SPDX-License-Identifier: MIT

// FIXTURE: init/constructor_vulnerable_critical
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-002
// SEVERITY: critical
// PATTERN: upgradeable constructor writes privileged state
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

contract CriticalConstructor is Initializable {
    address public owner;
    address public token;
    address public oracle;

    constructor(address owner_, address token_, address oracle_) {
        owner = owner_;
        token = token_;
        oracle = oracle_;
    }

    function initialize() external initializer {}
}

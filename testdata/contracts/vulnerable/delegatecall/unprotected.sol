// testdata/contracts/vulnerable/delegatecall/unprotected.sol
// SPDX-License-Identifier: MIT
// DETECTOR: delegatecall
// EXPECTED_FINDINGS: 1
// SEVERITY: CRITICAL
pragma solidity ^0.8.0;

contract UnprotectedDelegatecall {
    address public implementation;

    // Anyone can call this, and the implementation can be attacker-controlled.
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}

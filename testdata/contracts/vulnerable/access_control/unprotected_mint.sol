// testdata/contracts/vulnerable/access_control/unprotected_mint.sol
// SPDX-License-Identifier: MIT
// DETECTOR: access-control
// EXPECTED_FINDINGS: 1
// SEVERITY: CRITICAL
pragma solidity ^0.8.0;

contract UnprotectedMint {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Anyone can mint unlimited tokens.
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
}

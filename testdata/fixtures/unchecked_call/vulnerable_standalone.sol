// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 1
contract VulnerableStandaloneCall {
    function pay(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }
}

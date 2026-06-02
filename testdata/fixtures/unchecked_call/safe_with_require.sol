// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 0
contract SafeInlineCall {
    function pay(address payable to, uint256 amount) external {
        require(to.send(amount), "send failed");
    }
}

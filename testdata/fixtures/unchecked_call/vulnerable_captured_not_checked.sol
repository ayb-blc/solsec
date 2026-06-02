// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 1
contract VulnerableCapturedCall {
    event Paid(address indexed to, uint256 amount);

    function pay(address payable to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        emit Paid(to, amount);
    }
}

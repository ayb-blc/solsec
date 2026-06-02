// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 0
contract SafeCapturedCall {
    function pay(address payable to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 1
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;

    function withdraw() external {
        _sendFunds(msg.sender, balances[msg.sender]);
        balances[msg.sender] = 0;
    }

    function _sendFunds(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
}

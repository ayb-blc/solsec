// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 0
contract SafeOwnable {
    address public owner;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balanceOf[to] += amount;
    }
}

// testdata/contracts/safe/access_control/ownable_mint.sol
// SPDX-License-Identifier: MIT
// DETECTOR: access-control
// EXPECTED_FINDINGS: 0
pragma solidity ^0.8.0;

abstract contract Ownable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}

contract SafeMint is Ownable {
    mapping(address => uint256) public balances;

    // onlyOwner modifier provides access control
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}

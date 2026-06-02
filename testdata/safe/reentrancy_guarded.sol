// testdata/safe/reentrancy_guarded.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint) public balances;
    bool internal locked;

    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    // Safe path: guard is enabled.
    function withdraw() external nonReentrant {
        uint bal = balances[msg.sender];
        balances[msg.sender] = 0;
        
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent);
    }
}

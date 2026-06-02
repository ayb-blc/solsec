// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FIXTURE: reentrancy/safe_custom_mutex
// EXPECTED_FINDINGS: 0
// PATTERN: custom boolean mutex
contract SafeCustomMutex {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier noReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external noReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);

        balances[msg.sender] = 0;
    }
}
// testdata/contracts/safe/reentrancy/with_guard.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DETECTOR: reentrancy
// EXPECTED_FINDINGS: 0
// PATTERN: correctly protected with a local ReentrancyGuard-style modifier
//
// False-positive test: the tool must not produce findings for this contract.
// If it does, the detector is too aggressive.
//
// This fixture intentionally avoids importing OpenZeppelin. The detector only
// needs the security pattern signal (nonReentrant + lock), not the external
// dependency itself.
abstract contract ReentrancyGuard {
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }
}

contract SafeWithGuard is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // nonReentrant modifier means the ReentrancyGuard-style protection is active
    // This function is protected against reentrancy and should not produce a finding
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}

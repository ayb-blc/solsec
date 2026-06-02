// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FIXTURE: reentrancy/safe_nonreentrant
// EXPECTED_FINDINGS: 0
// PATTERN: protected by nonReentrant modifier
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeNonReentrant is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
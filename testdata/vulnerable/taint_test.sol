// testdata/vulnerable/taint_test.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TaintTestVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    // CASE 1: direct msg.value flow into transfer
    // Expected: SinkETHTransfer, TaintMsgValue, HIGH confidence
    function directFlow() external payable {
        payable(msg.sender).transfer(msg.value); // msg.value flows directly into the sink
    }

    // CASE 2: propagation chain
    // Expected: TaintCalldata -> amount -> fee -> net -> SinkETHTransfer
    function propagationChain(uint256 amount) external {
        uint256 fee = amount * 3 / 100;   // fee is tainted by amount
        uint256 net = amount - fee;        // net is tainted by amount and fee
        payable(msg.sender).transfer(net); // SINK — net tainted
    }

    // CASE 3: msg.sender → selfdestruct
    // Expected: CRITICAL, TaintMsgSender -> SinkSelfdestruct
    function dangerousDestruct() external {
        selfdestruct(payable(msg.sender)); // msg.sender tainted -> CRITICAL
    }

    // CASE 4: safe pattern with sanitized taint
    // Expected: no finding because require(balances[msg.sender] >= amount) bounds the value
    // NOTE: this is a false-positive regression test; the tool should not report it
    // Current limitation: sanitization detection may still be out of scope
    function safeWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // CASE 5: delegatecall with a tainted target
    // Expected: CRITICAL, TaintCalldata -> SinkDelegatecall
    function unsafeDelegatecall(address impl, bytes calldata data) external {
        (bool success,) = impl.delegatecall(data); // impl tainted!
        require(success);
    }
}

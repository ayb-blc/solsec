// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/safe_domain_separator.sol

// FIXTURE: signature_replay/safe_domain_separator
// EXPECTED_FINDINGS: 0
// PATTERN: manual DOMAIN_SEPARATOR (includes chainId) + nonce + deadline
pragma solidity ^0.8.0;

contract SafeManualEIP712 {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MyProtocol"),
            block.chainid,
            address(this)
        ));
    }

    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 hash = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(owner, spender, value, nonces[owner]++, deadline))
        ));
        require(ecrecover(hash, v, r, s) == owner, "invalid sig");
    }
}

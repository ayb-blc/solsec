// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/safe_eip712.sol

// FIXTURE: signature_replay/safe_eip712
// EXPECTED_FINDINGS: 0
// PATTERN: OZ EIP-712 with _hashTypedDataV4 - all protections included
pragma solidity ^0.8.0;

abstract contract EIP712 {
    function _hashTypedDataV4(bytes32 structHash) internal pure returns (bytes32) {
        return structHash;
    }
}

library ECDSA {
    function recover(bytes32 hash, uint8, bytes32, bytes32) internal pure returns (address) {
        return address(uint160(uint256(hash)));
    }
}

contract SafePermit is EIP712 {
    bytes32 private constant TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    mapping(address => uint256) public nonces;

    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        // _hashTypedDataV4 includes chainId via domain separator.
        address signer = ECDSA.recover(_hashTypedDataV4(structHash), v, r, s);
        require(signer == owner, "invalid sig");
    }
}

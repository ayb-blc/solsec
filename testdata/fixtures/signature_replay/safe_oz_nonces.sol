// SPDX-License-Identifier: MIT
// testdata/fixtures/signature_replay/safe_oz_nonces.sol

// FIXTURE: signature_replay/safe_oz_nonces
// EXPECTED_FINDINGS: 0
// PATTERN: OZ Nonces helper (_useNonce) + EIP-712
pragma solidity ^0.8.0;

abstract contract EIP712 {
    function _hashTypedDataV4(bytes32 structHash) internal pure returns (bytes32) {
        return structHash;
    }
}

abstract contract Nonces {
    mapping(address => uint256) private _nonces;

    function _useNonce(address owner) internal returns (uint256) {
        return _nonces[owner]++;
    }
}

library ECDSA {
    function recover(bytes32 hash, uint8, bytes32, bytes32) internal pure returns (address) {
        return address(uint160(uint256(hash)));
    }
}

contract SafeWithNonces is EIP712, Nonces {
    function execute(
        address target, bytes calldata data,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(
            abi.encode(keccak256("Execute(address target,bytes data,uint256 nonce,uint256 deadline)"),
                target, keccak256(data), _useNonce(msg.sender), deadline)
        );
        address signer = ECDSA.recover(_hashTypedDataV4(structHash), v, r, s);
        require(signer == msg.sender, "invalid sig");
        (bool ok,) = target.call(data);
        require(ok, "call failed");
    }
}

// SPDX-License-Identifier: MIT

// FIXTURE: init/gap_safe_with_gap
// EXPECTED_FINDINGS: 0
// PATTERN: upgradeable base contract includes a storage gap
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract SafeBase is Initializable {
    uint256 public fee;
    address public treasury;
    uint256[48] private __gap;

    function initialize() external initializer {}
}

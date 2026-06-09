// SPDX-License-Identifier: MIT
// testdata/fixtures/flash_loan/safe_aave_style.sol

// FIXTURE: flash_loan/safe_aave_style
// EXPECTED_FINDINGS: 0
// PATTERN: Aave-style executeOperation with caller check
pragma solidity ^0.8.0;

contract SafeAaveReceiver {
    address public immutable POOL;

    constructor(address pool) { POOL = pool; }

    function executeOperation(
        address[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        address,
        bytes calldata
    ) external view returns (bool) {
        require(msg.sender == POOL, "caller is not the lending pool");
        // ... flash loan logic ...
        return true;
    }
}

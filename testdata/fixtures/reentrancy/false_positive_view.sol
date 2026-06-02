// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// EXPECTED_FINDINGS: 0
interface IOracle {
    function price() external view returns (uint256);
}

contract ViewOnly {
    IOracle public oracle;

    function getPrice() external view returns (uint256) {
        return oracle.price();
    }
}

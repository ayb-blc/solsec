// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/safe_twap_v2_cumulative.sol

// FIXTURE: oracle/safe_twap_v2_cumulative
// EXPECTED_FINDINGS: 0
// PATTERN: Uniswap V2 TWAP using price0CumulativeLast
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function price0CumulativeLast() external view returns (uint256);
    function price1CumulativeLast() external view returns (uint256);
    function getReserves() external view returns (uint112, uint112, uint32);
}

// SAFE: uses cumulative prices (TWAP oracle pattern)
// getReserves() here is only used for timestamp, not for price
contract SafeTWAPOracle {
    IUniswapV2Pair public immutable pair;
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32  public blockTimestampLast;

    function update() external {
        (,, uint32 blockTimestamp) = pair.getReserves();
        uint32 elapsed = blockTimestamp - blockTimestampLast;
        if (elapsed > 0) {
            price0CumulativeLast = pair.price0CumulativeLast();
            blockTimestampLast = blockTimestamp;
        }
    }
}

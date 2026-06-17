// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/safe_twap_v3.sol

// FIXTURE: oracle/safe_twap_v3
// EXPECTED_FINDINGS: 0
// PATTERN: Uniswap V3 TWAP via pool.observe()
pragma solidity ^0.8.0;

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory, uint160[] memory);
}

contract SafeLendingV3 {
    IUniswapV3Pool public immutable pool;
    uint32 public constant TWAP_PERIOD = 1800; // 30 minutes

    constructor(address pool_) { pool = IUniswapV3Pool(pool_); }

    // SAFE: uses TWAP — requires sustained manipulation over 30 minutes
    function getTWAPPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDelta / int56(uint56(TWAP_PERIOD)));
        return uint256(uint160(getSqrtRatioAtTick(avgTick)));
    }

    function getSqrtRatioAtTick(int24) internal pure returns (uint160) {
        return 1;
    }
}

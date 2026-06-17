// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/vulnerable_amm_spot_price.sol

// FIXTURE: oracle/vulnerable_amm_spot_price
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-005
// SEVERITY: critical
// PATTERN: getReserves() used for pricing without TWAP
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract VulnerableLending {
    IUniswapV2Pair public immutable pair;

    constructor(address pair_) { pair = IUniswapV2Pair(pair_); }

    // VULNERABLE: spot price from AMM reserves
    // Flash loan can manipulate this in a single block
    function getTokenPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }

    function borrow(uint256 amount) external view returns (uint256) {
        uint256 price = getTokenPrice();  // manipulable!
        uint256 collateralRequired = amount * 1e18 / price;
        return collateralRequired;
    }
}

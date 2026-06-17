// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/safe_chainlink_full_validation.sol

// FIXTURE: oracle/safe_chainlink_full_validation
// EXPECTED_FINDINGS: 0
// PATTERN: Chainlink with staleness + validity check
pragma solidity ^0.8.0;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

contract SafeOracle {
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant MAX_DELAY = 3600; // 1 hour

    constructor(address feed) { priceFeed = AggregatorV3Interface(feed); }

    // SAFE: full Chainlink validation
    function getPrice() external view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(answer > 0,                           "Invalid price");
        require(updatedAt >= block.timestamp - MAX_DELAY, "Stale price");
        require(answeredInRound >= roundId,           "Incomplete round");

        return uint256(answer);
    }
}

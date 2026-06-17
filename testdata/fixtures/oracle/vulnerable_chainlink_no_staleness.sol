// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/vulnerable_chainlink_no_staleness.sol

// FIXTURE: oracle/vulnerable_chainlink_no_staleness
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-005
// SEVERITY: high
// PATTERN: latestRoundData without updatedAt check
pragma solidity ^0.8.0;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

contract VulnerableOracle {
    AggregatorV3Interface public immutable priceFeed;

    constructor(address feed) { priceFeed = AggregatorV3Interface(feed); }

    // VULNERABLE: no staleness check — stale price accepted
    function getPrice() external view returns (uint256) {
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Invalid price");
        return uint256(price);
        // Missing freshness validation for updatedAt.
    }
}

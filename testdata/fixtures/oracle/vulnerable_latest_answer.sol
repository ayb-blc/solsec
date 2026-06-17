// SPDX-License-Identifier: MIT
// testdata/fixtures/oracle/vulnerable_latest_answer.sol

// FIXTURE: oracle/vulnerable_latest_answer
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-005
// SEVERITY: high
// PATTERN: deprecated latestAnswer() — no round info available
pragma solidity ^0.8.0;

interface AggregatorInterface {
    function latestAnswer() external view returns (int256);
}

contract DeprecatedOracle {
    AggregatorInterface public immutable feed;

    constructor(address feed_) { feed = AggregatorInterface(feed_); }

    // VULNERABLE: deprecated function, no staleness possible
    function getPrice() external view returns (uint256) {
        int256 price = feed.latestAnswer();
        require(price > 0);
        return uint256(price);
    }
}

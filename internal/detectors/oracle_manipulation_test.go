// internal/detectors/oracle_manipulation_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestOracleManipulation_Fixtures(t *testing.T) {
	d := detectors.NewOracleManipulationDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/oracle/*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if fixture.ExpectedFindings == 0 && len(findings) != 0 {
				t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
			}
			if fixture.ExpectedFindings > 0 && len(findings) == 0 {
				t.Fatalf("expected at least one finding")
			}
		})
	}
}

func TestOracleManipulation_Critical_AMMSpotPrice(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Lending {
    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("getReserves for pricing = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestOracleManipulation_Safe_TWAPV3(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Safe {
    function getPrice() public view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800;
        (int56[] memory ticks,) = pool.observe(secondsAgos);
        return computePrice(ticks);
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("V3 TWAP = safe, got %d findings", len(findings))
	}
}

func TestOracleManipulation_High_ChainlinkNoStaleness(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Oracle {
    function getPrice() external view returns (uint256) {
        (, int256 price,,,) = feed.latestRoundData();
        require(price > 0);
        return uint256(price);
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("no staleness check = HIGH expected")
	}
	stalenessFound := false
	for _, f := range findings {
		if f.Severity == analyzer.High &&
			strings.Contains(f.Title, "staleness") {
			stalenessFound = true
		}
	}
	if !stalenessFound {
		t.Error("staleness finding not present")
	}
}

func TestOracleManipulation_Safe_ChainlinkFullValidation(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Safe {
    uint256 constant MAX_DELAY = 3600;
    function getPrice() external view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound)
            = feed.latestRoundData();
        require(answer > 0, "invalid");
        require(updatedAt >= block.timestamp - MAX_DELAY, "stale");
        require(answeredInRound >= roundId, "incomplete");
        return uint256(answer);
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("full validation = safe, got %d findings", len(findings))
	}
}

func TestOracleManipulation_Safe_SequencerUptimeFeed(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract PriceOracleSentinel {
    uint256 private _gracePeriod;
    ISequencerOracle private _sequencerOracle;

    function _isUpAndGracePeriodPassed() internal view returns (bool) {
        (, int256 answer, , uint256 lastUpdateTimestamp, ) = _sequencerOracle.latestRoundData();
        return answer == 0 && block.timestamp - lastUpdateTimestamp > _gracePeriod;
    }
}
interface ISequencerOracle {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("sequencer uptime feed = status oracle, got %d findings", len(findings))
	}
}

func TestOracleManipulation_High_DeprecatedLatestAnswer(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Deprecated {
    function getPrice() external view returns (uint256) {
        int256 price = feed.latestAnswer();
        return uint256(price);
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("latestAnswer() = HIGH expected")
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestOracleManipulation_Safe_V2TWAPCumulative(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract TWAP {
    // Uses cumulative price — not spot price
    uint256 public price0CumulativeLast;

    function update() external {
        (,, uint32 ts) = pair.getReserves();  // timestamp only
        price0CumulativeLast = pair.price0CumulativeLast();
    }
}`
	d := detectors.NewOracleManipulationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("V2 TWAP with cumulative = safe, got %d findings", len(findings))
	}
}

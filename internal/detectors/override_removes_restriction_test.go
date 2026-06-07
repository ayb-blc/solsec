package detectors_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestOverrideRemovesRestriction_Fixtures(t *testing.T) {
	d := detectors.NewOverrideRemovesRestrictionDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/override/*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(findings) != fixture.ExpectedFindings {
				t.Fatalf("findings = %d, want %d: %#v", len(findings), fixture.ExpectedFindings, findings)
			}
		})
	}
}

func TestOverrideRemovesRestriction_DropsOnlyOwner(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setFee(uint256 f) external virtual onlyOwner { fee = f; }
}
contract Child is Base {
    function setFee(uint256 f) external override { fee = f; }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("dropped onlyOwner with state write = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
	if findings[0].Confidence != analyzer.ConfidenceHigh {
		t.Errorf("same-file parent = HIGH confidence, got %v", findings[0].Confidence)
	}
}

func TestOverrideRemovesRestriction_KeepsModifier_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    modifier onlyOwner() { _; }
    function setFee(uint256 f) external virtual onlyOwner { fee = f; }
}
contract Child is Base {
    function setFee(uint256 f) external override onlyOwner { fee = f; }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("modifier preserved = no finding, got %d", len(findings))
	}
}

func TestOverrideRemovesRestriction_DifferentModifier_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    modifier onlyOwner() { _; }
    function setFee(uint256 f) external virtual onlyOwner {}
}
contract Child is Base {
    modifier onlyAdmin() { _; }
    function setFee(uint256 f) external override onlyAdmin {}
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("different but equivalent modifier = no finding, got %d", len(findings))
	}
}

func TestOverrideRemovesRestriction_ViewFunction_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    modifier onlyOwner() { _; }
    function getSecret() external view virtual onlyOwner returns (uint256) {
        return 42;
    }
}
contract Child is Base {
    function getSecret() external view override returns (uint256) {
        return 100;
    }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("view function = skip, got %d findings", len(findings))
	}
}

func TestOverrideRemovesRestriction_MultilineChildModifier_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    modifier onlyOwner() { _; }
    function setFee(uint256 f) external virtual onlyOwner { fee = f; }
}
contract Child is Base {
    function setFee(
        uint256 f
    )
        external
        override
        onlyOwner
    {
        fee = f;
    }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("multiline restricted override = no finding, got %d", len(findings))
	}
}

func TestOverrideRemovesRestriction_ParentNoModifier_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Base {
    function setFee(uint256 f) external virtual { fee = f; }
}
contract Child is Base {
    function setFee(uint256 f) external override { fee = f; }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("parent also had no modifier = no regression, got %d", len(findings))
	}
}

func TestOverrideRemovesRestriction_UnknownParent_NoHeuristicFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
import "./IPriceOracle.sol";
contract PriceOracle is IPriceOracle {
    uint256 public price;
    function setAssetPrice(address asset, uint256 newPrice) external override {
        asset;
        price = newPrice;
    }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("unknown cross-file parent should be skipped, got %d", len(findings))
	}
}

func TestOverrideRemovesRestriction_GrandparentChain(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract GrandParent {
    modifier onlyOwner() { _; }
    function pause() external virtual onlyOwner { _paused = true; }
}
contract Parent is GrandParent {
    // Parent preserves the modifier
    function pause() external virtual override onlyOwner { _paused = true; }
}
contract Child is Parent {
    // Child drops it from the grandparent chain
    function pause() external override { _paused = true; }
}`
	d := detectors.NewOverrideRemovesRestrictionDetector()
	findings, _ := d.Analyze(splitLines(source), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("grandparent chain: dropped modifier should be detected")
	}
}

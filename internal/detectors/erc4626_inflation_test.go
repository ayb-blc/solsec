// internal/detectors/erc4626_inflation_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestERC4626Inflation_Fixtures(t *testing.T) {
	d := detectors.NewERC4626InflationDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/erc4626/*.sol") {
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

func TestERC4626Inflation_Critical_NoProtection(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Vault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("V","V") {}
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("ERC4626 with no protection = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
	if findings[0].RuleID != "SOLSEC-DEFI-004" {
		t.Errorf("rule = %v, want SOLSEC-DEFI-004", findings[0].RuleID)
	}
}

func TestERC4626Inflation_Safe_DecimalsOffset(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Vault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("V","V") {}
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3;
    }
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("_decimalsOffset override = safe, got %d findings", len(findings))
	}
}

func TestERC4626Inflation_Safe_DeadShares(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Vault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("V","V") {}
    function _deposit(address c, address r, uint256 a, uint256 s) internal override {
        if (totalSupply() == 0) {
            _mint(address(0), 1000);
        }
        super._deposit(c, r, a, s);
    }
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("dead shares protection = safe, got %d findings", len(findings))
	}
}

func TestERC4626Inflation_Safe_PlusOneDenominator(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Vault is ERC4626 {
    function _convertToShares(uint256 assets, Math.Rounding r)
        internal view override returns (uint256) {
        return assets.mulDiv(
            totalSupply() + 1,
            totalAssets() + 1,
            r
        );
    }
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("totalAssets()+1 pattern = safe, got %d findings", len(findings))
	}
}

func TestERC4626Inflation_High_CustomVaultNoProtection(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract CustomVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        return totalShares == 0 ? assets : assets * totalShares / totalAssets();
    }
    function totalAssets() public view returns (uint256) { return 0; }
    function deposit(uint256 assets) external returns (uint256) { return 0; }
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("custom vault without protection = HIGH expected")
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("severity = %v, want HIGH (no explicit ERC4626 inheritance)", findings[0].Severity)
	}
}

func TestERC4626Inflation_NoFalsePositive_Abstract(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
abstract contract BaseVault is ERC4626 {
    // Abstract vault — no concrete implementation yet
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("abstract contract = skip, got %d findings", len(findings))
	}
}

func TestERC4626Inflation_NoFalsePositive_Interface(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
interface IERC4626Extended is IERC4626 {
    function totalAssets() external view returns (uint256);
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("interface = skip, got %d findings", len(findings))
	}
}

func TestERC4626Inflation_Safe_MulDivWithOffset(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract SafeVault is ERC4626 {
    constructor(IERC20 a) ERC4626(a) ERC20("V","V") {}

    function _convertToShares(uint256 assets, Math.Rounding r)
        internal view override returns (uint256) {
        // OZ v4.9 pattern: virtual shares via offset
        return assets.mulDiv(
            totalSupply() + 10 ** _decimalsOffset(),
            totalAssets() + 1,
            r
        );
    }
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3;
    }
}`
	d := detectors.NewERC4626InflationDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("OZ v4.9 pattern = safe, got %d findings", len(findings))
	}
}

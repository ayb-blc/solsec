// testdata/fixtures/erc4626/safe_plus_one_denominator.sol

// FIXTURE: erc4626/safe_plus_one_denominator
// EXPECTED_FINDINGS: 0
// PATTERN: manual +1 denominator in convertToShares
pragma solidity ^0.8.0;

contract SafeVaultManual {
    uint256 public totalAssetBalance;
    uint256 public totalShares;

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        // PROTECTED: +1 in denominator prevents 0-share deposits
        return supply == 0
            ? assets
            : assets * supply / (totalAssets() + 1);
    }

    function totalAssets() public view returns (uint256) {
        return totalAssetBalance;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        totalShares += shares;
        totalAssetBalance += assets;
    }
}
// testdata/fixtures/erc4626/vulnerable_interface_impl.sol

// FIXTURE: erc4626/vulnerable_interface_impl
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-004
// SEVERITY: high
// PATTERN: implements ERC4626 functions without protection
pragma solidity ^0.8.0;

// Custom ERC4626 implementation — no OZ, no protection
contract VulnerableCustomVault {
    uint256 public totalAssetBalance;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // VULNERABLE: naive division with no +1 protection
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalShares == 0) return assets;
        return assets * totalShares / totalAssets();
    }

    function totalAssets() public view returns (uint256) {
        return totalAssetBalance;
    }

    function deposit(uint256 assets) external returns (uint256 shareAmount) {
        shareAmount = convertToShares(assets);
        shares[msg.sender] += shareAmount;
        totalShares += shareAmount;
        totalAssetBalance += assets;
    }
}
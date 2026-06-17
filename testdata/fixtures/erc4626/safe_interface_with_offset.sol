// SPDX-License-Identifier: MIT
// testdata/fixtures/erc4626/safe_interface_with_offset.sol

// FIXTURE: erc4626/safe_interface_with_offset
// EXPECTED_FINDINGS: 0
// PATTERN: implements IERC4626 but has mulDiv with virtual offset
pragma solidity ^0.8.0;

interface IERC4626 {}

contract SafeCustomVault is IERC4626 {
    uint256 private constant SHARES_OFFSET = 1e6;

    function convertToShares(uint256 assets) public pure returns (uint256) {
        uint256 supply = totalSupply() + SHARES_OFFSET;
        return assets * supply / (totalAssets() + 1);
    }

    function totalAssets() public pure returns (uint256) { return 0; }
    function totalSupply() public pure returns (uint256) { return 0; }
    function deposit(uint256, address) external pure returns (uint256) { return 0; }
    function mint(uint256, address) external pure returns (uint256) { return 0; }
    function withdraw(uint256, address, address) external pure returns (uint256) { return 0; }
    function redeem(uint256, address, address) external pure returns (uint256) { return 0; }
}

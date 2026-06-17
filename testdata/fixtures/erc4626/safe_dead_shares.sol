// testdata/fixtures/erc4626/safe_dead_shares.sol

// FIXTURE: erc4626/safe_dead_shares
// EXPECTED_FINDINGS: 0
// PATTERN: dead shares minted to address(0) on first deposit
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SafeVaultDeadShares is ERC4626 {
    uint256 private constant DEAD_SHARES = 1000;

    constructor(IERC20 asset_)
        ERC4626(asset_)
        ERC20("Vault", "vTKN")
    {}

    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal virtual override {
        // PROTECTED: dead shares to address(0) on first deposit
        if (totalSupply() == 0) {
            _mint(address(0), DEAD_SHARES);
        }
        super._deposit(caller, receiver, assets, shares);
    }
}
// testdata/fixtures/erc4626/vulnerable_no_protection.sol

// FIXTURE: erc4626/vulnerable_no_protection
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-DEFI-004
// SEVERITY: critical
// PATTERN: ERC4626 inheritance, zero protection
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// VULNERABLE: uses OZ pre-4.9 default conversion
// shares = assets * totalSupply / totalAssets (no +1, no offset)
contract VulnerableVault is ERC4626 {
    constructor(IERC20 asset_)
        ERC4626(asset_)
        ERC20("Vault", "vTKN")
    {}

    // No _decimalsOffset override
    // No dead shares
    // No minimum deposit
}
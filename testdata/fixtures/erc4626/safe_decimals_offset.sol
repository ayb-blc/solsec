// testdata/fixtures/erc4626/safe_decimals_offset.sol

// FIXTURE: erc4626/safe_decimals_offset
// EXPECTED_FINDINGS: 0
// PATTERN: virtual shares via _decimalsOffset override
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SafeVaultOffset is ERC4626 {
    constructor(IERC20 asset_)
        ERC4626(asset_)
        ERC20("Vault", "vTKN")
    {}

    // PROTECTED: virtual shares make inflation attack economically infeasible
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3; // 1000x virtual shares
    }
}
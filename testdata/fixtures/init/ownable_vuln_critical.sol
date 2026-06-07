// SPDX-License-Identifier: MIT

// FIXTURE: init/ownable_vuln_critical
// EXPECTED_FINDINGS: 1
// RULE_ID: SOLSEC-INIT-004
// SEVERITY: high
// PATTERN: OwnableUpgradeable inherited but ownership is never initialized
pragma solidity ^0.8.0;

abstract contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract OwnableUpgradeable {
    address private _owner;
    uint256[49] private __gap;

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    function __Ownable_init() internal {
        _owner = msg.sender;
    }
}

contract VaultOwnableVulnerable is Initializable, OwnableUpgradeable {
    address public treasury;
    uint256[49] private __gap;

    function initialize(address treasury_) external initializer {
        treasury = treasury_;
    }

    function sweep() external onlyOwner {}
}

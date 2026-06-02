package onchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type ProxyKind string

const (
	ProxyUnknown     ProxyKind = "unknown"
	ProxyTransparent ProxyKind = "transparent"
	ProxyUUPS        ProxyKind = "uups"
	ProxyBeacon      ProxyKind = "beacon"
	ProxyMinimal     ProxyKind = "minimal"
)

type ProxyInfo struct {
	Kind                  ProxyKind
	ImplementationAddress ContractAddress
	AdminAddress          ContractAddress
	BeaconAddress         ContractAddress
	IsUpgradeable         bool
	Evidence              []string
}

type ProxyRisk struct {
	Title       string
	Description string
	Severity    string
}

type ProxyDetector struct {
	client *EtherscanClient
}

func NewProxyDetector(client *EtherscanClient) *ProxyDetector {
	return &ProxyDetector{client: client}
}

func (d *ProxyDetector) Detect(
	address ContractAddress,
	source *VerifiedSource,
	bytecode string,
) (*ProxyInfo, error) {
	if source == nil && strings.TrimSpace(bytecode) == "" {
		return nil, nil
	}

	text := ""
	if source != nil {
		text = source.ContractName + "\n" + source.SourceCode
		for name, content := range source.SourceFiles {
			text += "\n" + name + "\n" + content
		}
	}
	lower := strings.ToLower(text)
	bytecode = strings.ToLower(strings.TrimPrefix(bytecode, "0x"))

	info := &ProxyInfo{}
	switch {
	case strings.Contains(lower, "transparentupgradeableproxy"):
		info.Kind = ProxyTransparent
		info.IsUpgradeable = true
		info.Evidence = append(info.Evidence, "source references TransparentUpgradeableProxy")
	case strings.Contains(lower, "uups") || strings.Contains(lower, "upgradeeto") || strings.Contains(lower, "upgradeetoandcall"):
		info.Kind = ProxyUUPS
		info.IsUpgradeable = true
		info.Evidence = append(info.Evidence, "source references UUPS/upgradeTo")
	case strings.Contains(lower, "beaconproxy") || strings.Contains(lower, "upgradeablebeacon"):
		info.Kind = ProxyBeacon
		info.IsUpgradeable = true
		info.Evidence = append(info.Evidence, "source references Beacon proxy")
	case strings.Contains(bytecode, "363d3d373d3d3d363d73"):
		info.Kind = ProxyMinimal
		info.Evidence = append(info.Evidence, "bytecode matches EIP-1167 minimal proxy prefix")
	case strings.Contains(bytecode, "f4"):
		info.Kind = ProxyUnknown
		info.IsUpgradeable = true
		info.Evidence = append(info.Evidence, "runtime bytecode contains DELEGATECALL")
	default:
		return nil, nil
	}

	if impl := d.detectImplementationAddress(address, bytecode); impl != "" {
		info.ImplementationAddress = impl
	}
	if admin := d.readEIP1967Address(address, eip1967AdminSlot); admin != "" {
		info.AdminAddress = admin
	}
	if beacon := d.readEIP1967Address(address, eip1967BeaconSlot); beacon != "" {
		info.BeaconAddress = beacon
	}
	if info.Kind == "" {
		info.Kind = ProxyUnknown
	}
	return info, nil
}

func (d *ProxyDetector) AnalyzeProxy(info *ProxyInfo, address ContractAddress) []ProxyRisk {
	if info == nil {
		return nil
	}
	var risks []ProxyRisk
	if info.IsUpgradeable && info.AdminAddress == "" {
		risks = append(risks, ProxyRisk{
			Title:       fmt.Sprintf("Upgradeable proxy admin could not be verified for %s", address),
			Description: "The contract appears to be upgradeable, but the proxy admin slot or admin source path could not be verified. Review upgrade authorization manually.",
			Severity:    "medium",
		})
	}
	if info.ImplementationAddress == "" && info.Kind != ProxyMinimal {
		risks = append(risks, ProxyRisk{
			Title:       "Proxy implementation address could not be resolved",
			Description: "The proxy pattern was detected, but the implementation address was not recovered from bytecode or EIP-1967 storage.",
			Severity:    "high",
		})
	}
	return risks
}

const (
	eip1967ImplementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	eip1967AdminSlot          = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
	eip1967BeaconSlot         = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

func (d *ProxyDetector) detectImplementationAddress(address ContractAddress, bytecode string) ContractAddress {
	if impl := d.readEIP1967Address(address, eip1967ImplementationSlot); impl != "" {
		return impl
	}
	if impl := extractMinimalProxyImplementation(bytecode); impl != "" {
		return impl
	}
	return ""
}

func (d *ProxyDetector) readEIP1967Address(address ContractAddress, slot string) ContractAddress {
	if d == nil || d.client == nil {
		return ""
	}
	params := url.Values{}
	params.Set("module", "proxy")
	params.Set("action", "eth_getStorageAt")
	params.Set("address", string(address))
	params.Set("position", slot)
	params.Set("tag", "latest")
	params.Set("apikey", d.client.apiKey)

	resp, err := d.client.get(params)
	if err != nil {
		return ""
	}
	var raw string
	if err := json.Unmarshal(resp.Result, &raw); err != nil {
		return ""
	}
	return storageAddressFromRaw(raw)
}

func storageAddressFromRaw(raw string) ContractAddress {
	raw = strings.Trim(raw, `"`)
	raw = strings.TrimPrefix(raw, "0x")
	if len(raw) < 40 {
		return ""
	}
	addr := raw[len(raw)-40:]
	if addr == "0000000000000000000000000000000000000000" {
		return ""
	}
	return ContractAddress("0x" + strings.ToLower(addr))
}

func extractMinimalProxyImplementation(bytecode string) ContractAddress {
	bytecode = strings.TrimPrefix(strings.ToLower(bytecode), "0x")
	prefix := "363d3d373d3d3d363d73"
	idx := strings.Index(bytecode, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := start + 40
	if end > len(bytecode) {
		return ""
	}
	addr := bytecode[start:end]
	if _, err := hex.DecodeString(addr); err != nil {
		return ""
	}
	return ContractAddress("0x" + addr)
}

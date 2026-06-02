// cmd/solsec/onchain_cmd.go

package main

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/onchain"
)

func initOnChainFlags() {
	scanCmd.Flags().BoolVar(&onChainMode, "onchain", false, "Enable on-chain analysis via Etherscan")
	scanCmd.Flags().StringSliceVar(&onChainAddresses, "address", nil, "Contract addresses to analyze (0x...)")
	scanCmd.Flags().StringVar(&onChainNetwork, "network", string(onchain.NetworkEthereum), "Network: ethereum, polygon, arbitrum, optimism, bsc, base")
	scanCmd.Flags().StringVar(&etherscanAPIKey, "etherscan-key", "", "Etherscan API key (or set ETHERSCAN_API_KEY env var)")
	scanCmd.Flags().StringVar(&onChainLocalPath, "onchain-source", "", "Local source path for bytecode comparison")
}

func parseOnChainAddresses(raw []string) ([]onchain.ContractAddress, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("--onchain requires at least one --address")
	}

	addresses := make([]onchain.ContractAddress, 0, len(raw))
	for _, item := range raw {
		addr := strings.ToLower(strings.TrimSpace(item))
		if addr == "" {
			continue
		}
		if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
			return nil, fmt.Errorf("invalid contract address %q", item)
		}
		addresses = append(addresses, onchain.ContractAddress(addr))
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("--onchain requires at least one valid --address")
	}
	return addresses, nil
}

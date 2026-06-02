package onchain

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type MockEtherscan struct{}

func NewMockEtherscan() *MockEtherscan {
	return &MockEtherscan{}
}

func (m *MockEtherscan) Close() {}

func (m *MockEtherscan) Client() *EtherscanClient {
	client := NewEtherscanClient("test-key", NetworkEthereum)
	client.baseURL = "https://mock.etherscan.local/api"
	client.httpClient = &http.Client{Transport: mockEtherscanTransport{}}
	return client
}

type mockEtherscanTransport struct{}

func (mockEtherscanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	action := req.URL.Query().Get("action")
	var result any
	switch action {
	case "getsourcecode":
		result = []map[string]string{
			{
				"SourceCode":           `pragma solidity ^0.8.0; contract MockVault { function ok() external {} }`,
				"ABI":                  "[]",
				"ContractName":         "MockVault",
				"CompilerVersion":      "v0.8.20+commit.a1b79de6",
				"OptimizationUsed":     "1",
				"Runs":                 "200",
				"ConstructorArguments": "",
				"EVMVersion":           "default",
				"LicenseType":          "MIT",
			},
		}
	case "eth_getCode":
		result = "0x6080604052348015600f57600080fd5b50"
	case "eth_getStorageAt":
		result = "0x0000000000000000000000001234567890abcdef1234567890abcdef12345678"
	case "balance":
		result = "0"
	case "getcontractcreation":
		result = []map[string]string{{
			"contractAddress": req.URL.Query().Get("contractaddresses"),
			"contractCreator": "0x0000000000000000000000000000000000000001",
			"txHash":          "0xabc",
		}}
	default:
		result = []any{}
	}

	var body bytes.Buffer
	_ = json.NewEncoder(&body).Encode(map[string]any{
		"status":  "1",
		"message": "OK",
		"result":  result,
	})
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(&body),
		Request:    req,
	}, nil
}

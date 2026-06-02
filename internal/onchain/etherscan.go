package onchain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EtherscanClient Etherscan API istemcisi.
type EtherscanClient struct {
	apiKey      string
	network     Network
	baseURL     string
	httpClient  *http.Client
	rateLimiter *rateLimiter
}

func NewEtherscanClient(apiKey string, network Network) *EtherscanClient {
	base, ok := EtherscanBaseURL[network]
	if !ok {
		base = EtherscanBaseURL[NetworkEthereum]
	}
	return &EtherscanClient{
		apiKey:  apiKey,
		network: network,
		baseURL: base,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateLimiter: newRateLimiter(5), // 5 req/saniye
	}
}

// --- Etherscan API Response Types ---

type etherscanResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

type sourceCodeResult struct {
	SourceCode           string `json:"SourceCode"`
	ABI                  string `json:"ABI"`
	ContractName         string `json:"ContractName"`
	CompilerVersion      string `json:"CompilerVersion"`
	OptimizationUsed     string `json:"OptimizationUsed"`
	Runs                 string `json:"Runs"`
	ConstructorArguments string `json:"ConstructorArguments"`
	EVMVersion           string `json:"EVMVersion"`
	LicenseType          string `json:"LicenseType"`
}

type transactionResult struct {
	BlockNumber string `json:"blockNumber"`
	TimeStamp   string `json:"timeStamp"`
	Hash        string `json:"hash"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	Input       string `json:"input"`
	IsError     string `json:"isError"`
}

func (c *EtherscanClient) GetSourceCode(address ContractAddress) (*VerifiedSource, error) {
	c.rateLimiter.wait()

	params := url.Values{}
	params.Set("module", "contract")
	params.Set("action", "getsourcecode")
	params.Set("address", string(address))
	params.Set("apikey", c.apiKey)

	resp, err := c.get(params)
	if err != nil {
		return nil, fmt.Errorf("etherscan getsourcecode: %w", err)
	}

	var results []sourceCodeResult
	if err := json.Unmarshal(resp.Result, &results); err != nil {
		return nil, fmt.Errorf("parse source code response: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no source code found for %s", address)
	}

	r := results[0]
	if r.ABI == "Contract source code not verified" {
		return nil, nil
	}

	vs := &VerifiedSource{
		ContractName:         r.ContractName,
		CompilerVersion:      r.CompilerVersion,
		SourceCode:           r.SourceCode,
		ABI:                  r.ABI,
		ConstructorArguments: r.ConstructorArguments,
		EVMVersion:           r.EVMVersion,
		LicenseType:          r.LicenseType,
		OptimizationUsed:     r.OptimizationUsed == "1",
		VerifiedAt:           time.Now(),
	}

	runs, _ := strconv.Atoi(r.Runs)
	vs.OptimizationRuns = runs

	if strings.HasPrefix(r.SourceCode, "{{") {
		vs.SourceFiles = parseMultiFileSource(r.SourceCode)
	} else if strings.HasPrefix(r.SourceCode, "{") {
		// Standard JSON input format
		vs.SourceFiles = parseJSONInputSource(r.SourceCode)
	}

	return vs, nil
}

func (c *EtherscanClient) GetBytecode(address ContractAddress) (string, error) {
	c.rateLimiter.wait()

	params := url.Values{}
	params.Set("module", "proxy")
	params.Set("action", "eth_getCode")
	params.Set("address", string(address))
	params.Set("tag", "latest")
	params.Set("apikey", c.apiKey)

	resp, err := c.get(params)
	if err != nil {
		return "", fmt.Errorf("etherscan eth_getCode: %w", err)
	}

	var bytecode string
	if err := json.Unmarshal(resp.Result, &bytecode); err != nil {
		return "", fmt.Errorf("parse bytecode: %w", err)
	}

	bytecode = strings.TrimPrefix(bytecode, "0x")
	return bytecode, nil
}

func (c *EtherscanClient) GetBalance(address ContractAddress) (string, error) {
	c.rateLimiter.wait()

	params := url.Values{}
	params.Set("module", "account")
	params.Set("action", "balance")
	params.Set("address", string(address))
	params.Set("tag", "latest")
	params.Set("apikey", c.apiKey)

	resp, err := c.get(params)
	if err != nil {
		return "", err
	}

	var balance string
	if err := json.Unmarshal(resp.Result, &balance); err != nil {
		return "", err
	}
	return balance, nil
}

func (c *EtherscanClient) GetTransactions(
	address ContractAddress,
	limit int,
) ([]transactionResult, error) {
	c.rateLimiter.wait()

	params := url.Values{}
	params.Set("module", "account")
	params.Set("action", "txlist")
	params.Set("address", string(address))
	params.Set("startblock", "0")
	params.Set("endblock", "99999999")
	params.Set("page", "1")
	params.Set("offset", strconv.Itoa(limit))
	params.Set("sort", "desc")
	params.Set("apikey", c.apiKey)

	resp, err := c.get(params)
	if err != nil {
		return nil, err
	}

	var txs []transactionResult
	if err := json.Unmarshal(resp.Result, &txs); err != nil {
		return nil, err
	}
	return txs, nil
}

func (c *EtherscanClient) GetCreationTx(
	address ContractAddress,
) (*DeploymentInfo, error) {
	c.rateLimiter.wait()

	params := url.Values{}
	params.Set("module", "contract")
	params.Set("action", "getcontractcreation")
	params.Set("contractaddresses", string(address))
	params.Set("apikey", c.apiKey)

	resp, err := c.get(params)
	if err != nil {
		return nil, err
	}

	var results []struct {
		ContractAddress string `json:"contractAddress"`
		ContractCreator string `json:"contractCreator"`
		TxHash          string `json:"txHash"`
	}
	if err := json.Unmarshal(resp.Result, &results); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}

	return &DeploymentInfo{
		DeployerAddress:  results[0].ContractCreator,
		DeploymentTxHash: results[0].TxHash,
	}, nil
}

func (c *EtherscanClient) IsContract(address ContractAddress) (bool, error) {
	bytecode, err := c.GetBytecode(address)
	if err != nil {
		return false, err
	}
	return bytecode != "" && bytecode != "0x", nil
}

func (c *EtherscanClient) get(params url.Values) (*etherscanResponse, error) {
	reqURL := c.baseURL + "?" + params.Encode()

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}

	var result etherscanResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if result.Status == "0" && result.Message != "No transactions found" {
		return nil, fmt.Errorf("etherscan error: %s", result.Message)
	}

	return &result, nil
}

func parseMultiFileSource(source string) map[string]string {
	inner := strings.TrimPrefix(source, "{{")
	inner = strings.TrimSuffix(inner, "}}")

	var jsonInput struct {
		Sources map[string]struct {
			Content string `json:"content"`
		} `json:"sources"`
	}

	if err := json.Unmarshal([]byte(inner), &jsonInput); err != nil {
		return map[string]string{"main.sol": source}
	}

	files := make(map[string]string, len(jsonInput.Sources))
	for name, src := range jsonInput.Sources {
		files[name] = src.Content
	}
	return files
}

func parseJSONInputSource(source string) map[string]string {
	var jsonInput struct {
		Sources map[string]struct {
			Content string `json:"content"`
		} `json:"sources"`
	}

	if err := json.Unmarshal([]byte(source), &jsonInput); err != nil {
		return map[string]string{"main.sol": source}
	}

	files := make(map[string]string, len(jsonInput.Sources))
	for name, src := range jsonInput.Sources {
		files[name] = src.Content
	}
	return files
}

// rateLimiter basit token bucket rate limiter.
type rateLimiter struct {
	tokens chan struct{}
	done   chan struct{}
}

func newRateLimiter(rps int) *rateLimiter {
	rl := &rateLimiter{
		tokens: make(chan struct{}, rps),
		done:   make(chan struct{}),
	}
	for i := 0; i < rps; i++ {
		rl.tokens <- struct{}{}
	}
	// Periyodik olarak token ekle
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(rps))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) wait() {
	<-rl.tokens
}

func (rl *rateLimiter) Stop() {
	close(rl.done)
}

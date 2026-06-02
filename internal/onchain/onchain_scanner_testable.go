package onchain

func NewOnChainScannerWithClient(client *EtherscanClient) *OnChainScanner {
	return &OnChainScanner{
		fetcher:  NewSourceFetcher(client),
		detector: NewProxyDetector(client),
		ba:       NewBytecodeAnalyzer(),
	}
}

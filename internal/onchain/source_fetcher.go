package onchain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SourceFetcher struct {
	client        *EtherscanClient
	proxyDetector *ProxyDetector
}

type FetchedSource struct {
	Address        ContractAddress
	ContractName   string
	Files          map[string]string
	TempDir        string
	IsProxy        bool
	ProxyKind      ProxyKind
	Implementation ContractAddress
}

func NewSourceFetcher(client *EtherscanClient) *SourceFetcher {
	return &SourceFetcher{
		client:        client,
		proxyDetector: NewProxyDetector(client),
	}
}

func (f *SourceFetcher) Fetch(address ContractAddress) (*FetchedSource, error) {
	source, err := f.client.GetSourceCode(address)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("contract %s is not verified", address)
	}

	files := source.SourceFiles
	if len(files) == 0 {
		name := source.ContractName
		if name == "" {
			name = "Contract"
		}
		files = map[string]string{name + ".sol": source.SourceCode}
	}

	tempDir, err := os.MkdirTemp("", "solsec-onchain-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	fetched := &FetchedSource{
		Address:      address,
		ContractName: source.ContractName,
		Files:        files,
		TempDir:      tempDir,
	}

	if err := writeSourceFiles(tempDir, files); err != nil {
		fetched.Close()
		return nil, err
	}

	bytecode, _ := f.client.GetBytecode(address)
	if info, err := f.proxyDetector.Detect(address, source, bytecode); err == nil && info != nil {
		fetched.IsProxy = true
		fetched.ProxyKind = info.Kind
		fetched.Implementation = info.ImplementationAddress
	}

	return fetched, nil
}

func (f *FetchedSource) Close() error {
	if f == nil || f.TempDir == "" {
		return nil
	}
	return os.RemoveAll(f.TempDir)
}

func writeSourceFiles(root string, files map[string]string) error {
	for name, content := range files {
		cleanName := sanitizeSourcePath(name)
		path := filepath.Join(root, cleanName)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write source file %s: %w", cleanName, err)
		}
	}
	return nil
}

func sanitizeSourcePath(name string) string {
	name = filepath.ToSlash(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimPrefix(name, "./")
	if name == "" || strings.Contains(name, "..") {
		return "Contract.sol"
	}
	return name
}

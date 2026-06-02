package benchmark_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

func BenchmarkReentrancyDetector(b *testing.B) {
	d := detectors.NewReentrancyDetector()

	sizes := []struct {
		name     string
		numFuncs int
	}{
		{"small_contract", 5},
		{"medium_contract", 20},
		{"large_contract", 100},
	}

	for _, size := range sizes {
		size := size
		b.Run(size.name, func(b *testing.B) {
			source := generateContract(size.numFuncs)
			lines := strings.Split(source, "\n")

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := d.Analyze(lines, source, "bench.sol")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParallelScanning(b *testing.B) {
	files := make([]string, 50)
	for i := range files {
		f, _ := os.CreateTemp("", fmt.Sprintf("bench_%d_*.sol", i))
		f.WriteString(generateContract(10))
		f.Close()
		files[i] = f.Name()
	}
	defer func() {
		for _, f := range files {
			os.Remove(f)
		}
	}()

	workerCounts := []int{1, 2, 4, 8}

	for _, workers := range workerCounts {
		workers := workers
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			cfg := analyzer.Config{
				Workers: workers,
			}
			a := analyzer.New(
				[]analyzer.Detector{detectors.NewReentrancyDetector()},
				cfg,
			)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				results, err := a.ScanFiles(files)
				if err != nil {
					b.Fatal(err)
				}
				_ = results
			}
		})
	}
}

func generateContract(numFuncs int) string {
	var sb strings.Builder
	sb.WriteString("pragma solidity ^0.8.0;\ncontract BenchContract {\n")
	sb.WriteString("    mapping(address => uint256) public balances;\n\n")

	for i := 0; i < numFuncs; i++ {
		if i%3 == 0 {
			fmt.Fprintf(&sb, `
    function withdraw%d() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
`, i)
		} else {
			fmt.Fprintf(&sb, `
    function deposit%d() external payable {
        balances[msg.sender] += msg.value;
    }
`, i)
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

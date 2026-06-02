.PHONY: test test-unit test-integration test-accuracy test-bench test-race test-short test-detector coverage

GOCACHE ?= /tmp/solsec-gocache
export GOCACHE

test: test-unit test-integration

test-unit:
	@echo "-> Running unit tests..."
	go test ./internal/... -v -timeout 60s

test-integration:
	@echo "-> Running integration tests..."
	go test ./tests/integration/... -v -timeout 120s

test-accuracy:
	@echo "-> Measuring detector accuracy..."
	go test ./tests/accuracy/... -v -run TestDetectorAccuracy

test-race:
	@echo "-> Running race detector..."
	go test ./... -race -timeout 120s

test-bench:
	@echo "-> Running benchmarks..."
	go test ./tests/benchmark/... -bench=. -benchmem -count=3

test-short:
	go test ./... -short -timeout 30s

test-detector:
	@echo "-> Testing detector: $(DETECTOR)"
	go test ./internal/detectors/... -run "Test$(DETECTOR)" -v

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "-> Coverage report: coverage.html"
	go tool cover -func=coverage.out | tail -1

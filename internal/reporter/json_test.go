package reporter_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/reporter"
)

func TestJSONReporterNoFindingsUsesEmptyArrays(t *testing.T) {
	results := []analyzer.AnalysisResult{{Filepath: "contracts/Safe.sol"}}

	var buf bytes.Buffer
	r := reporter.NewJSON(&buf, false)
	if err := r.Report(results); err != nil {
		t.Fatalf("Report: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal json: %v\n%s", err, buf.String())
	}

	assertJSONArray(t, raw, "findings")
	assertJSONArray(t, raw, "by_file")
}

func assertJSONArray(t *testing.T, raw map[string]json.RawMessage, key string) {
	t.Helper()

	value, ok := raw[key]
	if !ok {
		t.Fatalf("missing %q field", key)
	}
	if string(value) == "null" {
		t.Fatalf("%q encoded as null, want []", key)
	}

	var arr []any
	if err := json.Unmarshal(value, &arr); err != nil {
		t.Fatalf("%q is not an array: %v", key, err)
	}
	if len(arr) != 0 {
		t.Fatalf("%q length = %d, want 0", key, len(arr))
	}
}

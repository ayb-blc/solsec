package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type Fixture struct {
	Path             string
	Name             string
	Source           string
	ExpectedFindings int
}

func LoadFixture(t *testing.T, path string) Fixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	source := string(data)
	return Fixture{
		Path:             path,
		Name:             strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Source:           source,
		ExpectedFindings: expectedFindings(path, source),
	}
}

func LoadFixtures(t *testing.T, pattern string) []Fixture {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob fixtures %s: %v", pattern, err)
	}
	fixtures := make([]Fixture, 0, len(paths))
	for _, path := range paths {
		fixtures = append(fixtures, LoadFixture(t, path))
	}
	return fixtures
}

func expectedFindings(path, source string) int {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "// EXPECTED_FINDINGS:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "// EXPECTED_FINDINGS:"))
		if value == "0" {
			return 0
		}
		return 1
	}
	if strings.Contains(filepath.Base(path), "vulnerable") || strings.Contains(filepath.Base(path), "cross_function") {
		return 1
	}
	return 0
}

func Lines(source string) []string {
	return strings.Split(source, "\n")
}

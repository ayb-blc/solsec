package parser

import (
	"fmt"
	"os"
)

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("readFile %s: %w", path, err)
	}
	return string(data), nil
}

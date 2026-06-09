// internal/inheritancegraph/resolver.go

package inheritancegraph

import (
	"os"
	"path/filepath"
	"strings"
)

// importResolver resolves Solidity import paths to absolute file paths.
// It handles relative imports and common package manager layouts
// (node_modules, Foundry lib/).
type importResolver struct {
	// Root directory of the project being scanned.
	rootDir string

	// Known search paths in resolution order.
	searchPaths []string
}

func newImportResolver(rootDir string) *importResolver {
	r := &importResolver{rootDir: rootDir}

	// Add common search paths in priority order.
	candidates := []string{
		rootDir,
		filepath.Join(rootDir, "node_modules"),
		filepath.Join(rootDir, "lib"),      // Foundry
		filepath.Join(rootDir, "packages"), // monorepo
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			r.searchPaths = append(r.searchPaths, c)
		}
	}

	return r
}

// Resolve attempts to turn an import path into an absolute file path.
// Returns empty string if the import cannot be resolved.
func (r *importResolver) Resolve(importPath string, currentFile string) string {
	// Relative import: resolve from the current file's directory.
	if strings.HasPrefix(importPath, ".") {
		dir := filepath.Dir(currentFile)
		candidate := filepath.Clean(filepath.Join(dir, importPath))
		if fileExists(candidate) {
			return candidate
		}
		return ""
	}

	// Absolute-style import (package import).
	// Strip leading "/" if present (rare but seen in some setups).
	importPath = strings.TrimPrefix(importPath, "/")

	for _, base := range r.searchPaths {
		candidate := filepath.Join(base, importPath)
		if fileExists(candidate) {
			return candidate
		}
	}

	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

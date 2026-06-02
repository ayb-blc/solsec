// Package cache provides persistent analysis result caching for incremental
// smart contract scans.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultMaxAge = 7 * 24 * time.Hour

// Cache stores per-file analysis results keyed by a stable path hash. Each
// entry also stores the file content hash, so path reuse cannot return stale
// findings after the source changes.
type Cache struct {
	dir         string
	entriesDir  string
	toolVersion string
	maxAge      time.Duration
}

// CacheEntry is the on-disk representation of one analyzed file.
type CacheEntry struct {
	Filepath         string            `json:"filepath"`
	FilePath         string            `json:"file_path,omitempty"`
	FileHash         string            `json:"file_hash"`
	ToolVersion      string            `json:"tool_version"`
	DetectorVersions map[string]string `json:"detector_versions,omitempty"`
	AnalyzedAt       time.Time         `json:"analyzed_at"`
	FindingCount     int               `json:"finding_count"`
	Findings         []CachedFinding   `json:"findings"`
}

// CachedFinding mirrors analyzer.Finding using primitive types so the cache
// package does not need to know about future analyzer enum internals.
type CachedFinding struct {
	DetectorName   string   `json:"detector"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Filepath       string   `json:"file"`
	Line           int      `json:"line"`
	CodeSnippet    string   `json:"code_snippet,omitempty"`
	Severity       int      `json:"severity"`
	Confidence     int      `json:"confidence"`
	Tags           []string `json:"tags,omitempty"`
}

// CacheStats summarizes the cache directory.
type CacheStats struct {
	Dir        string
	EntryCount int
	SizeBytes  int64
}

// Stats is kept as a compatibility alias for callers that used the shorter
// name before CacheStats became the public API.
type Stats = CacheStats

// New opens or creates an analysis cache.
func New(dir, toolVersion string) (*Cache, error) {
	if dir == "" {
		return nil, fmt.Errorf("cache dir is required")
	}
	if toolVersion == "" {
		return nil, fmt.Errorf("tool version is required")
	}

	c := &Cache{
		dir:         dir,
		entriesDir:  filepath.Join(dir, "entries"),
		toolVersion: toolVersion,
		maxAge:      defaultMaxAge,
	}
	if err := os.MkdirAll(c.entriesDir, 0o755); err != nil {
		return nil, err
	}
	return c, nil
}

// DefaultDir returns a deterministic per-project cache directory.
func DefaultDir(projectRoot string) string {
	if projectRoot == "" {
		projectRoot = "."
	}
	abs, err := filepath.Abs(projectRoot)
	if err == nil {
		projectRoot = abs
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	sum := sha256.Sum256([]byte(filepath.Clean(projectRoot)))
	return filepath.Join(base, "solsec", hex.EncodeToString(sum[:])[:16])
}

// HashFile returns the SHA-256 hash of a file's contents.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Get returns a valid cache entry for path, or nil on a cache miss.
func (c *Cache) Get(path string) (*CacheEntry, error) {
	currentHash, err := HashFile(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(c.entryPath(path))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		_ = os.Remove(c.entryPath(path))
		return nil, nil
	}

	if entry.FileHash != currentHash {
		return nil, nil
	}
	if entry.ToolVersion != c.toolVersion {
		return nil, nil
	}
	if !entry.AnalyzedAt.IsZero() && time.Since(entry.AnalyzedAt) > c.maxAge {
		return nil, nil
	}
	if entry.Filepath == "" {
		entry.Filepath = entry.FilePath
	}
	if entry.Filepath == "" {
		entry.Filepath = path
	}
	entry.FilePath = entry.Filepath
	for i := range entry.Findings {
		if entry.Findings[i].Filepath == "" {
			entry.Findings[i].Filepath = entry.Filepath
		}
	}
	return &entry, nil
}

// Set stores an analysis result for path. It computes metadata at write time
// so callers cannot accidentally cache stale hashes or tool versions.
func (c *Cache) Set(path string, entry *CacheEntry) error {
	if entry == nil {
		return fmt.Errorf("cache entry is nil")
	}
	fileHash, err := HashFile(path)
	if err != nil {
		return err
	}

	cp := *entry
	cp.Filepath = path
	cp.FilePath = path
	cp.FileHash = fileHash
	cp.ToolVersion = c.toolVersion
	cp.AnalyzedAt = time.Now().UTC()
	cp.FindingCount = len(cp.Findings)
	for i := range cp.Findings {
		if cp.Findings[i].Filepath == "" {
			cp.Findings[i].Filepath = path
		}
	}

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(c.entriesDir, "entry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, c.entryPath(path))
}

// Invalidate removes one file from the cache.
func (c *Cache) Invalidate(path string) error {
	err := os.Remove(c.entryPath(path))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Clear removes all cached entries while keeping the cache directory usable.
func (c *Cache) Clear() error {
	if err := os.RemoveAll(c.entriesDir); err != nil {
		return err
	}
	return os.MkdirAll(c.entriesDir, 0o755)
}

// Stats returns lightweight cache metrics.
func (c *Cache) Stats() CacheStats {
	stats := CacheStats{Dir: c.dir}
	_ = filepath.WalkDir(c.entriesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		stats.EntryCount++
		if info, err := d.Info(); err == nil {
			stats.SizeBytes += info.Size()
		}
		return nil
	})
	return stats
}

// IsSmartContractFile reports whether path is a supported smart contract file.
func IsSmartContractFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".sol" || ext == ".vy"
}

func (c *Cache) entryPath(path string) string {
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return filepath.Join(c.entriesDir, hex.EncodeToString(sum[:])+".json")
}

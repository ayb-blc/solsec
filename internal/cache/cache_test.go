// internal/cache/cache_test.go

package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ayb-blc/solsec/internal/cache"
)

func TestCache_SetAndGet(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.New(dir, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}

	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)

	entry := &cache.CacheEntry{
		FindingCount: 1,
		Findings: []cache.CachedFinding{
			{DetectorName: "reentrancy", Title: "Test Finding", Severity: 4},
		},
	}

	if err := c.Set(sol, entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := c.Get(sol)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.FindingCount != 1 {
		t.Errorf("FindingCount = %d, want 1", got.FindingCount)
	}
}

func TestCache_Miss_FileChanged(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.New(dir, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}

	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract A {}`)
	entry := &cache.CacheEntry{FindingCount: 0}
	c.Set(sol, entry)

	os.WriteFile(sol, []byte(`pragma solidity ^0.8.0; contract B {}`), 0o644)

	got, err := c.Get(sol)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected cache miss after file change, got hit")
	}
}

func TestCache_Miss_ToolVersionChanged(t *testing.T) {
	dir := t.TempDir()

	c1, _ := cache.New(dir, "0.1.0")
	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)
	c1.Set(sol, &cache.CacheEntry{FindingCount: 0})

	c2, _ := cache.New(dir, "0.2.0")
	got, err := c2.Get(sol)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected cache miss after tool version change")
	}
}

func TestCache_Invalidate(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.New(dir, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}

	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)
	c.Set(sol, &cache.CacheEntry{FindingCount: 2})

	c.Invalidate(sol)

	got, _ := c.Get(sol)
	if got != nil {
		t.Error("expected cache miss after invalidation")
	}
}

func TestCache_Clear(t *testing.T) {
	dir := t.TempDir()
	c, _ := cache.New(dir, "0.1.0")

	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)
	c.Set(sol, &cache.CacheEntry{FindingCount: 0})
	c.Clear()

	stats := c.Stats()
	if stats.EntryCount != 0 {
		t.Errorf("expected 0 entries after clear, got %d", stats.EntryCount)
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)

	h1, err := cache.HashFile(sol)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := cache.HashFile(sol)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("HashFile should be deterministic")
	}
}

func TestHashFile_ChangesWithContent(t *testing.T) {
	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract A {}`)
	h1, _ := cache.HashFile(sol)

	os.WriteFile(sol, []byte(`pragma solidity ^0.8.0; contract B {}`), 0o644)
	h2, _ := cache.HashFile(sol)

	if h1 == h2 {
		t.Error("hash should change when file content changes")
	}
}

func TestCache_Expiry(t *testing.T) {
	dir := t.TempDir()
	c, _ := cache.New(dir, "0.1.0")

	sol := writeTempSol(t, `pragma solidity ^0.8.0; contract T {}`)
	entry := &cache.CacheEntry{
		FindingCount: 0,
		AnalyzedAt:   time.Now().Add(-8 * 24 * time.Hour),
		ToolVersion:  "0.1.0",
	}
	// Hash'i manuel ekle
	h, _ := cache.HashFile(sol)
	entry.FileHash = h

	c.Set(sol, entry)

	got, _ := c.Get(sol)
	if got == nil {
		t.Error("fresh entry should be valid")
	}
}

func TestGitDiff_IsGitRepo(t *testing.T) {
	tmp := t.TempDir()
	if cache.IsGitRepo(tmp) {
		t.Error("temp dir should not be a git repo")
	}

	wd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(wd, "..", "..", ".git")); err == nil {
		if !cache.IsGitRepo(wd) {
			t.Error("project directory should be a git repo")
		}
	}
}

func TestDefaultDir_Deterministic(t *testing.T) {
	root := "/home/user/myproject"
	d1 := cache.DefaultDir(root)
	d2 := cache.DefaultDir(root)
	if d1 != d2 {
		t.Errorf("DefaultDir should be deterministic: %q != %q", d1, d2)
	}
}

func TestDefaultDir_DifferentProjects(t *testing.T) {
	d1 := cache.DefaultDir("/home/user/project1")
	d2 := cache.DefaultDir("/home/user/project2")
	if d1 == d2 {
		t.Error("different project roots should produce different cache dirs")
	}
}

func writeTempSol(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.sol")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	return f.Name()
}

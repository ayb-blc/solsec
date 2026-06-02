package cache

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// DiffStrategy controls which git changes are treated as analysis targets.
type DiffStrategy string

const (
	DiffStrategyDefault        DiffStrategy = "default"
	DiffStrategyStaged         DiffStrategy = "staged"
	DiffStrategyUnstaged       DiffStrategy = "unstaged"
	DiffStrategyAllUncommitted DiffStrategy = "uncommitted"
	DiffStrategyLastCommit     DiffStrategy = "last-commit"
)

// GitDiff wraps git diff file discovery for incremental scans.
type GitDiff struct {
	dir  string
	root string
}

// NewGitDiff creates a git diff helper rooted at the repository containing dir.
func NewGitDiff(dir string) (*GitDiff, error) {
	root, err := gitOutput(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("git root: %w", err)
	}
	return &GitDiff{
		dir:  strings.TrimSpace(dir),
		root: strings.TrimSpace(root),
	}, nil
}

// IsGitRepo reports whether dir is inside a git worktree.
func IsGitRepo(dir string) bool {
	_, err := gitOutput(dir, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

// ChangedFiles returns changed smart contract files for the selected strategy.
func (gd *GitDiff) ChangedFiles(strategy DiffStrategy) ([]string, error) {
	switch strategy {
	case DiffStrategyStaged:
		return gd.changed("--cached", "--name-only", "--diff-filter=ACMR")
	case DiffStrategyUnstaged:
		return gd.changed("--name-only", "--diff-filter=ACMR")
	case DiffStrategyAllUncommitted, DiffStrategyDefault, "":
		staged, err := gd.changed("--cached", "--name-only", "--diff-filter=ACMR")
		if err != nil {
			return nil, err
		}
		unstaged, err := gd.changed("--name-only", "--diff-filter=ACMR")
		if err != nil {
			return nil, err
		}
		untracked, err := gd.untracked()
		if err != nil {
			return nil, err
		}
		return uniquePaths(append(append(staged, unstaged...), untracked...)), nil
	case DiffStrategyLastCommit:
		return gd.changed("HEAD~1", "HEAD", "--name-only", "--diff-filter=ACMR")
	default:
		return nil, fmt.Errorf("unknown git diff strategy %q", strategy)
	}
}

// ChangedFilesSince returns smart contract files changed since ref.
func (gd *GitDiff) ChangedFilesSince(ref string) ([]string, error) {
	if strings.TrimSpace(ref) == "" {
		return gd.ChangedFiles(DiffStrategyDefault)
	}
	return gd.changed(strings.TrimSpace(ref), "--name-only", "--diff-filter=ACMR")
}

func (gd *GitDiff) changed(args ...string) ([]string, error) {
	fullArgs := append([]string{"diff"}, args...)
	out, err := gitOutput(gd.dir, fullArgs...)
	if err != nil {
		return nil, err
	}
	return gd.normalizeChangedOutput(out), nil
}

func (gd *GitDiff) untracked() ([]string, error) {
	out, err := gitOutput(gd.dir, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	return gd.normalizeChangedOutput(out), nil
}

func (gd *GitDiff) normalizeChangedOutput(out string) []string {
	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !IsSmartContractFile(line) {
			continue
		}
		files = append(files, filepath.Clean(filepath.Join(gd.root, line)))
	}
	return uniquePaths(files)
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return string(out), nil
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

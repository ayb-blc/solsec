// internal/inheritancegraph/builder.go

package inheritancegraph

import (
	"os"
	"path/filepath"
	"strings"
)

// Builder constructs a project-wide inheritance Graph by scanning all
// Solidity source files under a root directory.
type Builder struct {
	rootDir  string
	resolver *importResolver
	parser   *fileParser
}

// NewBuilder creates a Builder for the given project root.
func NewBuilder(rootDir string) *Builder {
	return &Builder{
		rootDir:  rootDir,
		resolver: newImportResolver(rootDir),
		parser:   newFileParser(),
	}
}

// BuildFromFiles constructs the inheritance graph from an explicit list
// of source files. All cross-file references are resolved against the
// project root.
func (b *Builder) BuildFromFiles(files []string) (*Graph, error) {
	g := NewGraph()

	// Pass 1: parse every file and create unlinked ContractNodes.
	// Store raw parse results keyed by filepath for the linking pass.
	allResults := make(map[string]*parseResult, len(files))

	for _, f := range files {
		lines, err := readLines(f)
		if err != nil {
			continue
		}
		result := b.parser.parse(f, lines)
		allResults[f] = result

		// Create ContractNodes from parsed declarations.
		for _, decl := range result.contracts {
			node := &ContractNode{
				Name:        decl.name,
				Filepath:    f,
				Kind:        decl.kind,
				Functions:   make(map[string]*FunctionNode),
				Modifiers:   make(map[string]*ModifierDef),
				SourceLines: decl.sourceLines,
				StateVars:   decl.stateVars,
			}

			// Attach functions
			for _, fd := range decl.functions {
				fn := &FunctionNode{
					Name:       fd.name,
					Signature:  fd.signature,
					Params:     fd.params,
					Modifiers:  fd.modifiers,
					Visibility: fd.visibility,
					Mutability: fd.mutability,
					Returns:    fd.returns,
					IsVirtual:  fd.isVirtual,
					IsOverride: fd.isOverride,
					LineNumber: fd.lineNumber,
					BodyLines:  fd.bodyLines,
					Contract:   node,
				}
				node.Functions[fd.name] = fn
			}

			for name, def := range decl.modifiers {
				copied := *def
				copied.Contract = node
				node.Modifiers[name] = &copied
			}

			g.addNode(node)
		}
	}

	// Pass 2: link parent references.
	// For each contract, resolve its parent names to ContractNode pointers.
	for f, result := range allResults {
		for i, decl := range result.contracts {
			// Find the corresponding node we created in pass 1.
			nodes := g.byName[decl.name]
			var node *ContractNode
			for _, n := range nodes {
				if n.Filepath == f {
					node = n
					break
				}
			}
			_ = i
			if node == nil {
				continue
			}

			for _, parentName := range decl.parentNames {
				parent := b.resolveParent(parentName, f, result.imports, g)
				if parent == nil {
					continue
				}
				node.Parents = append(node.Parents, parent)
				parent.Children = append(parent.Children, node)
			}
		}
	}

	g.EnrichFunctions()
	g.EnrichModifiers()
	return g, nil
}

func (b *Builder) BuildFromDir(dir string, excludePatterns []string) (*Graph, error) {
	files, err := collectSolFiles(dir, excludePatterns)
	if err != nil {
		return nil, err
	}
	return b.BuildFromFiles(files)
}

// resolveParent attempts to find a ContractNode for a parent name,
// using the importing file's import statements as hints.
func (b *Builder) resolveParent(
	parentName string,
	currentFile string,
	imports []string,
	g *Graph,
) *ContractNode {

	// 1. Check if the name is defined in the same file.
	for _, candidate := range g.byFile[currentFile] {
		if candidate.Name == parentName {
			return candidate
		}
	}

	// 2. Resolve import paths and look in imported files.
	for _, imp := range imports {
		resolved := b.resolver.Resolve(imp, currentFile)
		if resolved == "" {
			continue
		}
		for _, candidate := range g.byFile[resolved] {
			if candidate.Name == parentName {
				return candidate
			}
		}
	}

	// 3. Fall back to any contract with this name in the project.
	// Used when import resolution fails (e.g., uninstalled packages).
	if nodes := g.byName[parentName]; len(nodes) > 0 {
		return nodes[0]
	}

	return nil
}

// --- file system helpers ---

func collectSolFiles(root string, excludePatterns []string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sol") {
			return nil
		}
		if isExcluded(path, excludePatterns) {
			return nil
		}
		files = append(files, path)
		return nil
	})

	return files, err
}

func isExcluded(path string, patterns []string) bool {
	normalized := filepath.ToSlash(path)
	for _, pat := range patterns {
		pat = filepath.ToSlash(pat)
		if strings.Contains(normalized, strings.TrimSuffix(pat, "/**")) {
			return true
		}
		matched, _ := filepath.Match(pat, normalized)
		if matched {
			return true
		}
	}
	return false
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

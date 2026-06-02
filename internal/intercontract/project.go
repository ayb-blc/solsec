package intercontract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type ProjectLoader struct {
	registry *parser.ParserRegistry
}

func NewProjectLoader(registry *parser.ParserRegistry) *ProjectLoader {
	return &ProjectLoader{registry: registry}
}

type Project struct {
	Root string

	Files map[string]*ProjectFile

	ContractIndex map[string][]string

	ImportGraph map[string][]string
}

type ProjectFile struct {
	Path        string
	Language    parser.Language
	AST         *parser.UnifiedAST
	SymbolTable *symboltable.SymbolTable
	IndexDB     *symboltable.IndexDB
	Error       error
}

func (f *ProjectFile) Contracts() []*parser.UnifiedContract {
	if f.AST == nil {
		return nil
	}
	return f.AST.Contracts
}

func (l *ProjectLoader) LoadProject(root string) (*Project, error) {
	project := &Project{
		Root:          root,
		Files:         make(map[string]*ProjectFile),
		ContractIndex: make(map[string][]string),
		ImportGraph:   make(map[string][]string),
	}

	paths, err := collectFiles(root)
	if err != nil {
		return nil, fmt.Errorf("collect files: %w", err)
	}

	for _, path := range paths {
		file := l.loadFile(path)
		project.Files[path] = file

		if file.Error != nil || file.AST == nil {
			continue
		}

		for _, contract := range file.AST.Contracts {
			project.ContractIndex[contract.Name] = append(
				project.ContractIndex[contract.Name], path,
			)
		}

		sourceBytes, _ := os.ReadFile(path)
		imports := extractImports(string(sourceBytes), root, path)
		project.ImportGraph[path] = imports
	}

	return project, nil
}

func (l *ProjectLoader) loadFile(path string) *ProjectFile {
	file := &ProjectFile{
		Path:     path,
		Language: parser.DetectLanguage(path),
	}

	ast, err := l.registry.Parse(path)
	if err != nil {
		if fallback := lightweightParse(path); fallback != nil {
			file.AST = fallback
			return file
		}
		file.Error = err
		return file
	}
	file.AST = ast

	if file.Language == parser.LanguageSolidity && ast.Solidity != nil {
		if unit := ast.Solidity; unit != nil {
			sourceBytes, _ := os.ReadFile(path)
			srcMap := parser.NewSourceMap(string(sourceBytes))
			st, err := symboltable.Build(unit, srcMap)
			if err == nil {
				file.SymbolTable = st
			}
		}
	}

	return file
}

func lightweightParse(path string) *parser.UnifiedAST {
	sourceBytes, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	source := string(sourceBytes)
	ast := &parser.UnifiedAST{
		Language: parser.DetectLanguage(path),
		Filepath: path,
		Lines:    strings.Split(source, "\n"),
	}

	contractRe := regexp.MustCompile(`\b(contract|interface|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	functionRe := regexp.MustCompile(`\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*([^;{]*)`)
	for _, match := range contractRe.FindAllStringSubmatchIndex(source, -1) {
		kind := source[match[2]:match[3]]
		name := source[match[4]:match[5]]
		if strings.Contains(kind, "abstract") {
			kind = parser.ContractKindAbstract
		}
		contract := &parser.UnifiedContract{
			Name: name,
			Kind: kind,
		}

		bodyStart := strings.Index(source[match[1]:], "{")
		if bodyStart >= 0 {
			bodyStart += match[1]
			bodyEnd := findMatchingBrace(source, bodyStart)
			if bodyEnd > bodyStart {
				body := source[bodyStart:bodyEnd]
				for _, fnMatch := range functionRe.FindAllStringSubmatch(body, -1) {
					attrs := fnMatch[2]
					visibility := parser.VisibilityPublic
					for _, candidate := range []string{
						parser.VisibilityExternal,
						parser.VisibilityPublic,
						parser.VisibilityInternal,
						parser.VisibilityPrivate,
					} {
						if strings.Contains(attrs, candidate) {
							visibility = candidate
							break
						}
					}
					mutability := parser.MutabilityNonpayable
					for _, candidate := range []string{
						parser.MutabilityPayable,
						parser.MutabilityView,
						parser.MutabilityPure,
					} {
						if strings.Contains(attrs, candidate) {
							mutability = candidate
							break
						}
					}
					contract.Functions = append(contract.Functions, &parser.UnifiedFunction{
						Name:       fnMatch[1],
						Visibility: visibility,
						Mutability: mutability,
					})
				}
			}
		}
		ast.Contracts = append(ast.Contracts, contract)
	}
	if len(ast.Contracts) == 0 {
		return nil
	}
	return ast
}

func findMatchingBrace(source string, open int) int {
	depth := 0
	for i := open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (p *Project) ContractFile(contractName string) (*ProjectFile, bool) {
	paths, ok := p.ContractIndex[contractName]
	if !ok || len(paths) == 0 {
		return nil, false
	}
	file, ok := p.Files[paths[0]]
	return file, ok
}

func (p *Project) AllContracts() []*ContractInProject {
	var contracts []*ContractInProject
	for path, file := range p.Files {
		if file.AST == nil {
			continue
		}
		for _, contract := range file.AST.Contracts {
			contracts = append(contracts, &ContractInProject{
				Contract: contract,
				File:     file,
				Filepath: path,
			})
		}
	}
	return contracts
}

type ContractInProject struct {
	Contract *parser.UnifiedContract
	File     *ProjectFile
	Filepath string
}

func extractImports(source, root, currentFile string) []string {
	var imports []string
	dir := filepath.Dir(currentFile)

	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import") {
			continue
		}

		start := strings.IndexAny(line, `"'`)
		end := strings.LastIndexAny(line, `"'`)
		if start < 0 || start == end {
			continue
		}
		importPath := line[start+1 : end]

		var abs string
		if strings.HasPrefix(importPath, ".") {
			abs = filepath.Join(dir, importPath)
		} else {
			abs = filepath.Join(root, "node_modules", importPath)
			if _, err := os.Stat(abs); os.IsNotExist(err) {
				abs = filepath.Join(root, importPath)
			}
		}

		abs = filepath.Clean(abs)
		if _, err := os.Stat(abs); err == nil {
			imports = append(imports, abs)
		}
	}
	return imports
}

func collectFiles(root string) ([]string, error) {
	var files []string
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	absRoot = filepath.Clean(absRoot)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if filepath.Clean(abs) != absRoot &&
				(name == "node_modules" || strings.HasPrefix(name, ".") ||
					name == "lib" || name == "out" || name == "artifacts") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".sol") || strings.HasSuffix(path, ".vy") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

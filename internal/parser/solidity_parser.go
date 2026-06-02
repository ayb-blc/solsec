package parser

import (
	"os"
	"path/filepath"
	"strings"
)

type SolidityParser struct {
	runner *SolcRunner
}

func NewSolidityParser(solcPath string) *SolidityParser {
	return &SolidityParser{runner: NewSolcRunner(solcPath)}
}

func (p *SolidityParser) Language() Language { return LanguageSolidity }

func (p *SolidityParser) CanParse(path string) bool {
	return filepath.Ext(path) == ".sol"
}

func (p *SolidityParser) IsAvailable() bool {
	return p.runner != nil && p.runner.IsAvailable()
}

func (p *SolidityParser) Parse(path string) (*UnifiedAST, error) {
	unit, err := p.runner.ParseFile(path)
	if err != nil {
		return nil, err
	}
	out := &UnifiedAST{
		Language: LanguageSolidity,
		Filepath: path,
		Solidity: unit,
	}
	if content, err := os.ReadFile(path); err == nil {
		out.Lines = strings.Split(string(content), "\n")
	}
	if unit == nil {
		return out, nil
	}
	for _, node := range unit.Nodes {
		if node == nil || node.ContractDef == nil {
			continue
		}
		cd := node.ContractDef
		contract := &UnifiedContract{
			Name:    cd.Name,
			Kind:    cd.ContractKind,
			Parents: make([]string, 0, len(cd.BaseContracts)),
		}
		for _, base := range cd.BaseContracts {
			if base.BaseName.Name != "" {
				contract.Parents = append(contract.Parents, base.BaseName.Name)
			}
		}
		for _, child := range cd.Nodes {
			switch {
			case child != nil && child.FunctionDef != nil:
				fd := child.FunctionDef
				fn := &UnifiedFunction{
					Name:       fd.Name,
					Visibility: fd.Visibility,
					Mutability: fd.StateMutability,
					Line:       lineFromSrc(child.Src),
					Raw:        child,
				}
				if fd.Parameters != nil {
					for _, p := range fd.Parameters.Parameters {
						if p == nil {
							continue
						}
						fn.Parameters = append(fn.Parameters, &UnifiedVariable{
							Name:            p.Name,
							Type:            TypeNameString(p.TypeName),
							Line:            lineFromSrc(p.Src),
							StorageLocation: StorageLocationKind(p.StorageLocation),
							Raw:             p,
						})
					}
				}
				for _, mod := range fd.Modifiers {
					if mod != nil && mod.ModifierInvoc != nil {
						fn.Modifiers = append(fn.Modifiers, mod.ModifierInvoc.ModifierName.Name)
					}
				}
				contract.Functions = append(contract.Functions, fn)
			case child != nil && child.StateVarDecl != nil:
				for _, v := range child.StateVarDecl.Variables {
					if v != nil {
						contract.StateVars = append(contract.StateVars, &UnifiedStateVariable{
							Name: v.Name,
							Type: TypeNameString(v.TypeName),
							Line: lineFromSrc(child.Src),
							Raw:  v,
						})
					}
				}
			}
		}
		out.Contracts = append(out.Contracts, contract)
	}
	return out, nil
}

func lineFromSrc(_ string) int {
	return 0
}

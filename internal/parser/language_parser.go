package parser

type Language string

const (
	LanguageUnknown  Language = ""
	LanguageSolidity Language = "solidity"
	LanguageVyper    Language = "vyper"
)

const (
	ContractKindInterface = "interface"
	ContractKindLibrary   = "library"
	ContractKindAbstract  = "abstract"
	ContractKindContract  = "contract"
)

const (
	VisibilityPublic   = "public"
	VisibilityExternal = "external"
	VisibilityInternal = "internal"
	VisibilityPrivate  = "private"
	VisibilityDefault  = ""
)

const (
	MutabilityPayable    = "payable"
	MutabilityPure       = "pure"
	MutabilityView       = "view"
	MutabilityNonpayable = "nonpayable"
)

const (
	VariableMutabilityMutable   = "mutable"
	VariableMutabilityConstant  = "constant"
	VariableMutabilityImmutable = "immutable"
)

type StorageLocationKind string

const (
	StorageLocationStorage  StorageLocationKind = "storage"
	StorageLocationMemory   StorageLocationKind = "memory"
	StorageLocationCalldata StorageLocationKind = "calldata"
	StorageLocationStack    StorageLocationKind = "stack"
)

const (
	StatementKindExpressionStatement = "expression"
	StatementKindVarDecl             = "variable_declaration"
	StatementKindAssignment          = "assignment"
	StatementKindReturn              = "return"
	StatementKindEmit                = "emit"
	StatementKindIf                  = "if"
	StatementKindFor                 = "for"
	StatementKindExternalCall        = "external_call"
	StatementKindInternalCall        = "internal_call"
)

type LanguageParser interface {
	Language() Language
	CanParse(path string) bool
	Parse(path string) (*UnifiedAST, error)
	IsAvailable() bool
}

type UnifiedAST struct {
	Language  Language
	Filepath  string
	Lines     []string
	Contracts []*UnifiedContract

	Solidity *SourceUnit
	Vyper    *VyperModule
}

type UnifiedContract struct {
	Name      string
	Kind      string
	Parents   []string
	Functions []*UnifiedFunction
	StateVars []*UnifiedStateVariable
}

type UnifiedFunction struct {
	Name       string
	Visibility string
	Mutability string
	Modifiers  []string
	Parameters []*UnifiedVariable
	Line       int
	Body       []*UnifiedStatement
	Raw        any
}

type UnifiedStateVariable struct {
	Name            string
	Type            string
	Line            int
	Visibility      string
	Mutability      string
	StorageLocation StorageLocationKind
	Raw             any
}

type UnifiedVariable = UnifiedStateVariable

type UnifiedStatement struct {
	Kind                 string
	Line                 int
	Text                 string
	ContainsExternalCall bool
	WritesState          bool
	Raw                  any
}

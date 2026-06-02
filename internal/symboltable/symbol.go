package symboltable

import "github.com/ayb-blc/solsec/internal/parser"

type SymbolKind int

const (
	KindStateVariable SymbolKind = iota
	KindLocalVariable
	KindParameter
	KindReturnVariable // Named return variable
	KindFunction
	KindModifier
	KindEvent
	KindError
	KindStruct
	KindEnum
	KindConstant
	KindImmutable
)

func (k SymbolKind) String() string {
	switch k {
	case KindStateVariable:
		return "state_variable"
	case KindLocalVariable:
		return "local_variable"
	case KindParameter:
		return "parameter"
	case KindReturnVariable:
		return "return_variable"
	case KindFunction:
		return "function"
	case KindModifier:
		return "modifier"
	case KindEvent:
		return "event"
	case KindStruct:
		return "struct"
	case KindConstant:
		return "constant"
	case KindImmutable:
		return "immutable"
	default:
		return "unknown"
	}
}

// calldata: read-only external input
type StorageLocation int

const (
	LocationStorage StorageLocation = iota
	LocationMemory
	LocationCalldata // Read-only external input
	LocationStack
	LocationUnknown
)

type Symbol struct {
	// --- Identity ---
	Name string
	Kind SymbolKind

	SolcID int

	// --- Tip Bilgisi ---
	TypeName        string // "uint256", "mapping(address => uint256)", vb.
	StorageLocation StorageLocation
	Mutability      string // "mutable", "immutable", "constant"
	Visibility      string // "public", "private", "internal", "external"

	// --- Declaration Lokasyonu ---
	DeclaredInScope *Scope
	DeclarationNode *parser.ASTNode // AST'deki declaration node'u

	// --- Usage Tracking ---
	Reads  []Usage
	Writes []Usage

	// --- Security Flags ---
	IsUserControlled bool

	// WrittenAfterExternalCall indicates a potential CEI violation.
	WrittenAfterExternalCall bool
}

type Usage struct {
	Node       *parser.ASTNode
	ScopeID    ScopeID
	InFunction string
	AfterCall  bool
}

func (s *Symbol) IsStateVariable() bool {
	return s.Kind == KindStateVariable
}

func (s *Symbol) IsWritable() bool {
	return s.Mutability != "constant" && s.Mutability != "immutable"
}

func (s *Symbol) WriteCount() int { return len(s.Writes) }

func (s *Symbol) ReadCount() int { return len(s.Reads) }

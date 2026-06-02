package taint_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
	"github.com/ayb-blc/solsec/internal/taint"
)

func TestIsTaintedBy_SameSymbol(t *testing.T) {
	db := symboltable.NewIndexDB()
	table := &symboltable.SymbolTable{}
	tr := taint.NewTaintRelation(db, table)

	sym := &symboltable.Symbol{SolcID: 1, Name: "x"}
	if tr.IsTaintedBy(sym, sym) {
		t.Error("symbol should not taint itself")
	}
}

func TestIsTaintedBy_DifferentFunction(t *testing.T) {
	db := symboltable.NewIndexDB()
	table := &symboltable.SymbolTable{}
	tr := taint.NewTaintRelation(db, table)

	src := &symboltable.Symbol{
		SolcID: 1, Name: "src",
		Reads: []symboltable.Usage{
			{InFunction: "foo", ScopeID: 10},
		},
	}
	candidate := &symboltable.Symbol{
		SolcID: 2, Name: "candidate",
		Writes: []symboltable.Usage{
			{InFunction: "bar", ScopeID: 20},
		},
	}

	if tr.IsTaintedBy(candidate, src) {
		t.Error("different functions should not produce taint relation")
	}
}

func TestIsTaintedBy_WriteAfterRead_SameScope(t *testing.T) {
	// Scenario:
	//   stmt 0: amount = msg.value  (src READ @ index 0)
	//   stmt 1: fee = amount * 3    (candidate WRITE @ index 1, RHS contains src)
	//
	// Expected: IsTaintedBy(fee, amount) == true

	db := symboltable.NewIndexDB()

	// amount'un read'ini index 0'a kaydet
	amountReadNode := &parser.ASTNode{ID: 100}
	db.ForceRegister(100, symboltable.StatementIndex{
		TopLevel: 0, FunctionScopeID: 10, NodeID: 100,
	})

	feeWriteNode := &parser.ASTNode{ID: 200}
	db.ForceRegister(200, symboltable.StatementIndex{
		TopLevel: 1, FunctionScopeID: 10, NodeID: 200,
	})

	src := &symboltable.Symbol{
		SolcID: 1, Name: "amount",
		Reads: []symboltable.Usage{
			{Node: amountReadNode, InFunction: "withdraw", ScopeID: 10},
		},
	}
	candidate := &symboltable.Symbol{
		SolcID: 2, Name: "fee",
		Writes: []symboltable.Usage{
			{Node: feeWriteNode, InFunction: "withdraw", ScopeID: 10},
		},
	}

	table := &symboltable.SymbolTable{AllSymbols: []*symboltable.Symbol{src, candidate}}
	tr := taint.NewTaintRelation(db, table)

	if !tr.IsTaintedBy(candidate, src) {
		t.Error("fee should be tainted by amount (write after read, same scope)")
	}
}

func TestIsTaintedBy_WriteBeforeRead_NotTainted(t *testing.T) {
	// Senaryo:
	// stmt 0: fee = someConst      (candidate WRITE @ index 0)
	// stmt 1: amount = msg.value   (src READ @ index 1)
	//

	db := symboltable.NewIndexDB()

	feeWriteNode := &parser.ASTNode{ID: 300}
	db.ForceRegister(300, symboltable.StatementIndex{
		TopLevel: 0, FunctionScopeID: 10, NodeID: 300,
	})

	amountReadNode := &parser.ASTNode{ID: 400}
	db.ForceRegister(400, symboltable.StatementIndex{
		TopLevel: 1, FunctionScopeID: 10, NodeID: 400,
	})

	src := &symboltable.Symbol{
		SolcID: 1, Name: "amount",
		Reads: []symboltable.Usage{
			{Node: amountReadNode, InFunction: "withdraw", ScopeID: 10},
		},
	}
	candidate := &symboltable.Symbol{
		SolcID: 2, Name: "fee",
		Writes: []symboltable.Usage{
			{Node: feeWriteNode, InFunction: "withdraw", ScopeID: 10},
		},
	}

	table := &symboltable.SymbolTable{AllSymbols: []*symboltable.Symbol{src, candidate}}
	tr := taint.NewTaintRelation(db, table)

	if tr.IsTaintedBy(candidate, src) {
		t.Error("fee written before amount read — should NOT be tainted")
	}
}

func TestIsTaintedBy_NestedBlock(t *testing.T) {
	// Senaryo:
	// stmt 0: amount = msg.value   (src READ @ TopLevel:0)
	// stmt 1: if (...) {
	//   stmt 1.0.0: fee = amount   (candidate WRITE @ TopLevel:1, NestedPath:[0,0])
	// }
	//
	// Expected: IsTaintedBy(fee, amount) == true
	// The nested write happens after the top-level read.

	db := symboltable.NewIndexDB()

	amountReadNode := &parser.ASTNode{ID: 500}
	db.ForceRegister(500, symboltable.StatementIndex{
		TopLevel: 0, FunctionScopeID: 10, NodeID: 500,
	})

	feeWriteNode := &parser.ASTNode{ID: 600}
	db.ForceRegister(600, symboltable.StatementIndex{
		TopLevel:        1,
		NestedPath:      []int{0, 0},
		FunctionScopeID: 10,
		NodeID:          600,
	})

	src := &symboltable.Symbol{
		SolcID: 1, Name: "amount",
		Reads: []symboltable.Usage{
			{Node: amountReadNode, InFunction: "withdraw", ScopeID: 10},
		},
	}
	candidate := &symboltable.Symbol{
		SolcID: 2, Name: "fee",
		Writes: []symboltable.Usage{
			{Node: feeWriteNode, InFunction: "withdraw", ScopeID: 10},
		},
	}

	table := &symboltable.SymbolTable{AllSymbols: []*symboltable.Symbol{src, candidate}}
	tr := taint.NewTaintRelation(db, table)

	if !tr.IsTaintedBy(candidate, src) {
		t.Error("fee in nested if-block after amount read — should be tainted")
	}
}

func TestStatementIndex_Before(t *testing.T) {
	cases := []struct {
		a, b symboltable.StatementIndex
		want bool
		name string
	}{
		{
			name: "earlier top level",
			a:    symboltable.StatementIndex{TopLevel: 0, FunctionScopeID: 1},
			b:    symboltable.StatementIndex{TopLevel: 1, FunctionScopeID: 1},
			want: true,
		},
		{
			name: "later top level",
			a:    symboltable.StatementIndex{TopLevel: 2, FunctionScopeID: 1},
			b:    symboltable.StatementIndex{TopLevel: 1, FunctionScopeID: 1},
			want: false,
		},
		{
			name: "same top, nested earlier",
			a:    symboltable.StatementIndex{TopLevel: 1, NestedPath: []int{0}, FunctionScopeID: 1},
			b:    symboltable.StatementIndex{TopLevel: 1, NestedPath: []int{1}, FunctionScopeID: 1},
			want: true,
		},
		{
			name: "parent before child (same top, shorter path)",
			a:    symboltable.StatementIndex{TopLevel: 1, NestedPath: nil, FunctionScopeID: 1},
			b:    symboltable.StatementIndex{TopLevel: 1, NestedPath: []int{0}, FunctionScopeID: 1},
			want: true,
		},
		{
			name: "different function scope — not before",
			a:    symboltable.StatementIndex{TopLevel: 0, FunctionScopeID: 1},
			b:    symboltable.StatementIndex{TopLevel: 5, FunctionScopeID: 2},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.a.Before(tc.b)
			if got != tc.want {
				t.Errorf("Before() = %v, want %v", got, tc.want)
			}
		})
	}
}

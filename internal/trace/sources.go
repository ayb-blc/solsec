// internal/trace/sources.go
// Convenience constructors that build traces from analysis engine types.

package trace

import (
	"strings"

	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

// FromCEIViolation builds a reentrancy trace from an ordered FunctionStateMap.
//
// Example output:
//
//	READ   balances[msg.sender]       Vault.sol:41  (require check)
//	CALL   msg.sender.call()          Vault.sol:43  ← external call
//	WRITE  balances[msg.sender] -= x  Vault.sol:44  ← write after call ❌
func FromCEIViolation(
	m *inheritancegraph.FunctionStateMap,
	v inheritancegraph.CEIViolation,
) *Trace {

	b := NewBuilder(
		"State write to '" + v.WriteAfter.VarName +
			"' after external call in '" + m.Function.Name + "'",
	)

	// Replay all ops up to and including the violated write
	callSeen := false
	writeSeen := false

	for _, op := range m.Ops {
		loc := Location{
			Filepath: m.Contract.Filepath,
			Line:     op.LineNum,
		}

		switch op.Kind {
		case inheritancegraph.OpRead:
			if !callSeen {
				loc.Snippet = op.Access.Line
				b.Read(op.Access.FullExpr, loc, "check")
			}

		case inheritancegraph.OpExternalCall:
			loc.Snippet = op.Call.Line
			if op.LineNum == v.ExternalCall.LineNum {
				b.Call(
					op.Call.Callee+"."+op.Call.Method+"()",
					loc, "external call; reentrancy window opens here",
				)
				callSeen = true
			} else if !callSeen {
				b.Call(op.Call.Callee+"."+op.Call.Method+"()", loc, "")
			}

		case inheritancegraph.OpWrite:
			loc.Snippet = op.Access.Line
			if callSeen && !writeSeen && op.Access.VarName == v.WriteAfter.VarName {
				b.WriteIssue(
					op.Access.FullExpr,
					loc,
					"write AFTER external call; CEI violation",
				)
				writeSeen = true
			} else if !callSeen {
				b.Write(op.Access.FullExpr, loc, "effect before interaction")
			}
		}

		if callSeen && writeSeen {
			break
		}
	}

	return b.Build()
}

// FromOverrideChain builds a trace for the override-removes-restriction detector.
//
// Example output:
//
//	INHERITS  Child is Base                Child.sol:3
//	OVERRIDE  Base.pause()  [onlyOwner]    Base.sol:15  (root definition)
//	OVERRIDE  Child.pause() []             Child.sol:42  ← modifier dropped ❌
func FromOverrideChain(
	chain *inheritancegraph.OverrideChain,
	regressionLink *inheritancegraph.OverrideLink,
	droppedDef *inheritancegraph.ModifierDef,
) *Trace {

	b := NewBuilder(
		"Modifier '" + droppedDef.Name + "' (" + droppedDef.Category.String() +
			") removed in override of '" + chain.FunctionName + "'",
	)

	// Walk chain from root to tip
	for i := len(chain.Links) - 1; i >= 0; i-- {
		link := chain.Links[i]
		loc := Location{
			Filepath: link.Contract.Filepath,
			Line:     link.Function.LineNumber,
			Snippet:  link.Function.Signature,
		}

		mods := link.Function.Modifiers
		modStr := ""
		if len(mods) > 0 {
			modStr = "[" + strings.Join(mods, ", ") + "]"
		} else {
			modStr = "(no modifier)"
		}

		detail := link.Contract.Name + "." + chain.FunctionName + "() " + modStr

		if link.IsRoot {
			b.Override(detail, loc, "root definition")
		} else if link.Contract == regressionLink.Contract {
			b.OverrideIssue(detail, loc,
				"dropped '"+droppedDef.Name+"' — access control removed here",
			)
		} else {
			note := ""
			if len(link.ModifiersAdded) > 0 {
				note = "added: " + strings.Join(link.ModifiersAdded, ", ")
			} else if len(link.ModifiersRemoved) > 0 {
				note = "removed: " + strings.Join(link.ModifiersRemoved, ", ")
			}
			b.Override(detail, loc, note)
		}
	}

	b.Effect(
		"Any caller can now invoke '"+chain.FunctionName+"()' without restriction",
		Location{}, "",
	)

	return b.Build()
}

// FromUninitializedOwnable builds a trace for the uninitialized-ownable detector.
//
// Example output:
//
//	INHERITS  Vault is OwnableUpgradeable  Vault.sol:5
//	DECLARES  function initialize()        Vault.sol:12
//	MISSING   __Ownable_init() not called
//	EFFECT    proxy.owner = address(0) — all onlyOwner calls revert
func FromUninitializedOwnable(
	contract *inheritancegraph.ContractNode,
	initFn *inheritancegraph.FunctionNode,
	missingCall string,
) *Trace {

	b := NewBuilder(
		"OwnableUpgradeable initializer not called in '" + contract.Name + ".initialize()'",
	)

	contractLoc := Location{Filepath: contract.Filepath, Line: 1}

	// Show inheritance
	for _, p := range contract.Parents {
		if strings.Contains(p.Name, "Ownable") {
			b.Inherits(
				contract.Name+" is "+p.Name,
				contractLoc,
				"upgradeable ownership requires explicit initialization",
			)
		}
	}

	// Show initialize declaration
	if initFn != nil {
		b.Info(
			"function initialize() declared",
			Location{
				Filepath: contract.Filepath,
				Line:     initFn.LineNumber,
				Snippet:  initFn.Signature,
			},
			"proxy entry point for initialization",
		)
	}

	// The missing call
	b.Missing(
		missingCall+" not called",
		Location{Filepath: contract.Filepath},
		"owner is never set on the proxy",
	)

	b.Effect(
		"proxy.owner = address(0) after deployment",
		Location{},
		"every onlyOwner call reverts — contract permanently locked",
	)

	return b.Build()
}

// FromFlashLoan builds a trace for a flash loan provider CEI violation.
func FromFlashLoan(
	fn *inheritancegraph.FunctionNode,
	contract *inheritancegraph.ContractNode,
	stateWriteBefore string, lineWriteBefore int,
	callbackLine string, lineCallback int,
	stateWriteAfter string, lineWriteAfter int,
) *Trace {

	b := NewBuilder(
		"State written before and after user-controlled callback in '" + fn.Name + "'",
	)

	if stateWriteBefore != "" {
		b.Write(stateWriteBefore,
			Location{Filepath: contract.Filepath, Line: lineWriteBefore, Snippet: stateWriteBefore},
			"state written — accounting begins",
		)
	}

	b.CallIssue(callbackLine,
		Location{Filepath: contract.Filepath, Line: lineCallback, Snippet: callbackLine},
		"user-controlled callback — attacker re-enters here",
	)

	if stateWriteAfter != "" {
		b.Write(stateWriteAfter,
			Location{Filepath: contract.Filepath, Line: lineWriteAfter, Snippet: stateWriteAfter},
			"state inconsistent during callback window",
		)
	}

	b.Effect(
		"attacker can exploit inconsistent state during callback",
		Location{},
		"Euler Finance ($197M) used this exact pattern",
	)

	return b.Build()
}

// FromSignatureReplay builds a trace for missing replay protection.
func FromSignatureReplay(
	fn *inheritancegraph.FunctionNode,
	contract *inheritancegraph.ContractNode,
	missingFields []string,
) *Trace {

	b := NewBuilder(
		"Signature replay: ecrecover() in '" + fn.Name + "' missing " +
			strings.Join(missingFields, ", "),
	)

	b.Info(
		"ecrecover() called",
		Location{Filepath: contract.Filepath, Line: fn.LineNumber},
		"signature verification without full replay protection",
	)

	for _, field := range missingFields {
		switch field {
		case "nonce":
			b.Missing("nonce not included in signed data",
				Location{Filepath: contract.Filepath},
				"same signature can be replayed on this chain indefinitely",
			)
		case "chainId":
			b.Missing("chainId not included in signed data",
				Location{Filepath: contract.Filepath},
				"signature valid on all chains running this contract",
			)
		case "deadline":
			b.Missing("deadline/expiry not included in signed data",
				Location{Filepath: contract.Filepath},
				"signature never expires",
			)
		}
	}

	b.Effect(
		"attacker who observes a valid signature can reuse it",
		Location{},
		"",
	)

	return b.Build()
}

package taint

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type TaintLabel int

const (
	TaintNone TaintLabel = iota
	TaintMsgSender
	TaintMsgValue
	TaintMsgData
	TaintTxOrigin
	TaintCalldata
	TaintBlockTimestamp
	TaintBlockNumber // block.number
	TaintDerived
)

func (t TaintLabel) String() string {
	switch t {
	case TaintMsgSender:
		return "msg.sender"
	case TaintMsgValue:
		return "msg.value"
	case TaintMsgData:
		return "msg.data"
	case TaintTxOrigin:
		return "tx.origin"
	case TaintCalldata:
		return "calldata-param"
	case TaintBlockTimestamp:
		return "block.timestamp"
	case TaintBlockNumber:
		return "block.number"
	case TaintDerived:
		return "derived"
	default:
		return "none"
	}
}

func (t TaintLabel) SecurityRisk() string {
	switch t {
	case TaintMsgSender:
		return "Access control bypass: attacker can control which address this resolves to"
	case TaintMsgValue:
		return "ETH amount manipulation: attacker controls the ETH value flowing through the contract"
	case TaintMsgData:
		return "Arbitrary calldata: attacker controls raw call payload"
	case TaintTxOrigin:
		return "Phishing risk: tx.origin is controllable via intermediate contract"
	case TaintCalldata:
		return "User-supplied input: external caller controls this value"
	case TaintBlockTimestamp:
		return "Timestamp manipulation: miners can influence block.timestamp by ~15 seconds"
	case TaintBlockNumber:
		return "Block number is predictable and can be used for front-running"
	case TaintDerived:
		return "Derived from tainted source: inherits the risk of its origin"
	default:
		return ""
	}
}

type TaintSource struct {
	Label       TaintLabel
	OriginNode  *parser.ASTNode
	Description string
}

type TaintedValue struct {
	Symbol *symboltable.Symbol

	Sources []TaintSource

	PropagationChain []*symboltable.Symbol

	ReachesSink bool

	SinkNode *parser.ASTNode

	SinkKind SinkKind
}

func (tv *TaintedValue) IsTainted() bool {
	return len(tv.Sources) > 0
}

func (tv *TaintedValue) AddSource(src TaintSource) {
	for _, existing := range tv.Sources {
		if existing.Label == src.Label {
			return // Zaten var
		}
	}
	tv.Sources = append(tv.Sources, src)
}

func (tv *TaintedValue) HighestRiskSource() TaintSource {
	// Priority: MsgSender > MsgValue > TxOrigin > Calldata > Derived > others
	priority := map[TaintLabel]int{
		TaintMsgSender:      6,
		TaintMsgValue:       5,
		TaintTxOrigin:       4,
		TaintCalldata:       3,
		TaintMsgData:        2,
		TaintBlockTimestamp: 1,
		TaintDerived:        0,
	}

	var best TaintSource
	bestPriority := -1
	for _, src := range tv.Sources {
		if p := priority[src.Label]; p > bestPriority {
			bestPriority = p
			best = src
		}
	}
	return best
}

func (tv *TaintedValue) PropagationPath() string {
	if len(tv.PropagationChain) == 0 {
		if len(tv.Sources) > 0 {
			return tv.Sources[0].Label.String() + " → " + tv.Symbol.Name
		}
		return tv.Symbol.Name
	}

	path := tv.HighestRiskSource().Label.String()
	for _, sym := range tv.PropagationChain {
		path += " → " + sym.Name
	}
	path += " → " + tv.Symbol.Name
	return path
}

type SinkKind int

const (
	SinkNone         SinkKind = iota
	SinkExternalCall          // addr.call{value: tainted}("")
	SinkETHTransfer           // addr.transfer(tainted)
	SinkSelfdestruct          // selfdestruct(tainted)
	SinkDelegatecall          // addr.delegatecall(tainted)
	SinkStorageWrite          // sstore(tainted_slot, ...)
	SinkAccessControl
	SinkArithmeticOp
)

func (sk SinkKind) String() string {
	switch sk {
	case SinkExternalCall:
		return "external-call"
	case SinkETHTransfer:
		return "eth-transfer"
	case SinkSelfdestruct:
		return "selfdestruct"
	case SinkDelegatecall:
		return "delegatecall"
	case SinkStorageWrite:
		return "storage-write"
	case SinkAccessControl:
		return "access-control"
	case SinkArithmeticOp:
		return "arithmetic"
	default:
		return "unknown"
	}
}

func (sk SinkKind) Severity() string {
	switch sk {
	case SinkSelfdestruct, SinkDelegatecall:
		return "CRITICAL"
	case SinkExternalCall, SinkETHTransfer:
		return "HIGH"
	case SinkAccessControl, SinkStorageWrite:
		return "HIGH"
	case SinkArithmeticOp:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

type TaintFlow struct {
	SourceLabel TaintLabel
	SourceNode  *parser.ASTNode

	Chain []*symboltable.Symbol

	SinkNode *parser.ASTNode
	SinkKind SinkKind

	FunctionName string
	ContractName string
}

func (tf *TaintFlow) String() string {
	return fmt.Sprintf(
		"[%s] %s → ... → %s (in %s.%s)",
		tf.SinkKind,
		tf.SourceLabel,
		tf.SinkKind,
		tf.ContractName,
		tf.FunctionName,
	)
}

package onchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type BytecodeAnalyzer struct {
	patterns []bytecodePattern
}

type bytecodePattern struct {
	name        string
	description string
	sequence    string // hex string
	opcode      string
	severity    analyzer.Severity
}

func NewBytecodeAnalyzer() *BytecodeAnalyzer {
	return &BytecodeAnalyzer{
		patterns: []bytecodePattern{
			{
				name:        "selfdestruct",
				description: "Contract contains SELFDESTRUCT opcode — can destroy the contract",
				sequence:    "ff",
				opcode:      "SELFDESTRUCT",
				severity:    analyzer.Critical,
			},
			{
				name:        "delegatecall",
				description: "Contract uses DELEGATECALL — potential proxy/upgrade pattern or vulnerability",
				sequence:    "f4",
				opcode:      "DELEGATECALL",
				severity:    analyzer.High,
			},
			{
				name:        "callcode",
				description: "Contract uses deprecated CALLCODE opcode",
				sequence:    "f2",
				opcode:      "CALLCODE",
				severity:    analyzer.High,
			},
			{
				name:        "create2",
				description: "Contract uses CREATE2 — verify deployment address is not manipulable",
				sequence:    "f5",
				opcode:      "CREATE2",
				severity:    analyzer.Medium,
			},
			{
				name:        "tx_origin",
				description: "Contract reads tx.origin — potential authentication vulnerability",
				sequence:    "32",
				opcode:      "ORIGIN",
				severity:    analyzer.High,
			},
			{
				// Solidity compiler metadata hash
				name:        "metadata_hash",
				description: "Metadata hash found — useful for exact source verification",
				sequence:    "a265627a7a72305820",
				opcode:      "METADATA",
				severity:    analyzer.Info,
			},
		},
	}
}

func (ba *BytecodeAnalyzer) Compare(
	onChain string,
	local string,
) *BytecodeComparisonResult {
	result := &BytecodeComparisonResult{
		OnChainBytecodeHash: hashHex(onChain),
		LocalBytecodeHash:   hashHex(local),
	}

	onChain = normalize(onChain)
	local = normalize(local)

	if onChain == "" {
		result.MatchType = MatchNoSource
		return result
	}

	if local == "" {
		result.MatchType = MatchUnverified
		return result
	}

	// Exact match
	if onChain == local {
		result.Match = true
		result.MatchType = MatchExact
		result.MetadataMatch = true
		return result
	}

	// Solidity compiler bytecode sonuna metadata hash ekler.
	onChainNoMeta := stripMetadata(onChain)
	localNoMeta := stripMetadata(local)

	if onChainNoMeta == localNoMeta {
		result.Match = true
		result.MatchType = MatchPartial
		result.MetadataMatch = false

		onChainMeta := extractMetadataHash(onChain)
		localMeta := extractMetadataHash(local)
		result.SwarmHash = onChainMeta
		if onChainMeta != "" && localMeta != "" {
			result.MetadataMatch = onChainMeta == localMeta
		}
		return result
	}

	result.Match = false
	result.MatchType = MatchMismatch
	result.Differences = findDifferences(onChainNoMeta, localNoMeta)

	return result
}

func (ba *BytecodeAnalyzer) AnalyzePatterns(bytecode string) []SuspiciousPattern {
	bytecode = normalize(bytecode)
	if bytecode == "" {
		return nil
	}

	var patterns []SuspiciousPattern
	seen := make(map[string]bool)

	for _, p := range ba.patterns {
		if seen[p.name] {
			continue
		}

		idx := strings.Index(bytecode, p.sequence)
		if idx < 0 {
			continue
		}

		// Byte offset (hex string'de 2 karakter = 1 byte)
		byteOffset := idx / 2

		patterns = append(patterns, SuspiciousPattern{
			Name:         p.name,
			Description:  p.description,
			Offset:       byteOffset,
			Opcode:       p.opcode,
			Severity:     p.severity,
			ByteSequence: p.sequence,
		})
		seen[p.name] = true
	}

	return patterns
}

func (ba *BytecodeAnalyzer) DecompileBasic(bytecode string) []OpcodeEntry {
	bytecode = normalize(bytecode)
	if bytecode == "" {
		return nil
	}

	data, err := hex.DecodeString(bytecode)
	if err != nil {
		return nil
	}

	var entries []OpcodeEntry
	i := 0
	for i < len(data) {
		op := data[i]
		name, pushLen := opcodeName(op)

		entry := OpcodeEntry{
			Offset: i,
			Opcode: op,
			Name:   name,
		}

		if pushLen > 0 && i+1+pushLen <= len(data) {
			entry.Data = data[i+1 : i+1+pushLen]
			i += 1 + pushLen
		} else {
			i++
		}

		entries = append(entries, entry)
	}

	return entries
}

type OpcodeEntry struct {
	Offset int
	Opcode byte
	Name   string
	Data   []byte
}

func (e OpcodeEntry) String() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("%04x: %s 0x%s", e.Offset, e.Name, hex.EncodeToString(e.Data))
	}
	return fmt.Sprintf("%04x: %s", e.Offset, e.Name)
}

func (ba *BytecodeAnalyzer) ExtractFunctionSelectors(bytecode string) []string {
	bytecode = normalize(bytecode)
	data, err := hex.DecodeString(bytecode)
	if err != nil {
		return nil
	}

	var selectors []string
	seen := make(map[string]bool)

	// PUSH4 opcode = 0x63
	for i := 0; i < len(data)-5; i++ {
		if data[i] == 0x63 { // PUSH4
			sel := hex.EncodeToString(data[i+1 : i+5])
			if !seen[sel] && isLikelySelector(data, i) {
				selectors = append(selectors, "0x"+sel)
				seen[sel] = true
			}
		}
	}

	return selectors
}

func isLikelySelector(data []byte, pushOffset int) bool {
	if pushOffset+5 >= len(data) {
		return false
	}
	next := data[pushOffset+5]
	// DUP1 (0x80), EQ (0x14), GT (0x11), LT (0x10)
	return next == 0x80 || next == 0x14 || next == 0x11 || next == 0x10
}

func normalize(hex string) string {
	hex = strings.TrimPrefix(hex, "0x")
	hex = strings.TrimSpace(hex)
	return strings.ToLower(hex)
}

func hashHex(data string) string {
	h := sha256.Sum256([]byte(normalize(data)))
	return hex.EncodeToString(h[:])
}

// Metadata format:
//
//	Solidity < 0.6: 0xa165627a7a72305820 + <32 bytes> + 0029
//	Solidity >= 0.6: 0xa2646970667358221220 + <32 bytes> + 64736f6c63 + version + 0033
func stripMetadata(bytecode string) string {
	// IPFS metadata prefix (Solidity >= 0.6)
	ipfsPrefix := "a2646970667358221220"
	if idx := strings.LastIndex(bytecode, ipfsPrefix); idx >= 0 {
		return bytecode[:idx]
	}

	for _, swarmPrefix := range []string{
		"a165627a7a72305820", // Solidity legacy Swarm metadata
		"a265627a7a72305820", // Common CBOR Swarm marker variant
	} {
		if idx := strings.LastIndex(bytecode, swarmPrefix); idx >= 0 {
			return bytecode[:idx]
		}
	}

	return bytecode
}

func extractMetadataHash(bytecode string) string {
	ipfsPrefix := "a2646970667358221220"
	if idx := strings.LastIndex(bytecode, ipfsPrefix); idx >= 0 {
		start := idx + len(ipfsPrefix)
		if start+64 <= len(bytecode) {
			return bytecode[start : start+64]
		}
	}

	for _, swarmPrefix := range []string{
		"a165627a7a72305820",
		"a265627a7a72305820",
	} {
		if idx := strings.LastIndex(bytecode, swarmPrefix); idx >= 0 {
			start := idx + len(swarmPrefix)
			if start+64 <= len(bytecode) {
				return bytecode[start : start+64]
			}
			return bytecode[start:]
		}
	}

	return ""
}

func findDifferences(a, b string) []BytecodeDiff {
	var diffs []BytecodeDiff

	aBytes, err1 := hex.DecodeString(a)
	bBytes, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return diffs
	}

	minLen := len(aBytes)
	if len(bBytes) < minLen {
		minLen = len(bBytes)
	}

	i := 0
	for i < minLen {
		if aBytes[i] != bBytes[i] {
			start := i
			for i < minLen && aBytes[i] != bBytes[i] {
				i++
			}
			diffs = append(diffs, BytecodeDiff{
				Offset:       start,
				OnChainBytes: aBytes[start:i],
				LocalBytes:   bBytes[start:i],
				Description: fmt.Sprintf(
					"Difference at offset 0x%x (%d bytes)",
					start, i-start,
				),
			})
		} else {
			i++
		}
	}

	if len(aBytes) != len(bBytes) {
		shorter, longer := aBytes, bBytes
		desc := "on-chain bytecode is longer"
		if len(bBytes) < len(aBytes) {
			shorter, longer = bBytes, aBytes
			desc = "local bytecode is longer"
		}
		diffs = append(diffs, BytecodeDiff{
			Offset:       len(shorter),
			OnChainBytes: longer[len(shorter):],
			Description:  fmt.Sprintf("%s by %d bytes", desc, len(longer)-len(shorter)),
		})
	}

	return diffs
}

func opcodeName(op byte) (string, int) {
	opcodes := map[byte]string{
		0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB",
		0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
		0x08: "ADDMOD", 0x09: "MULMOD", 0x0a: "EXP", 0x0b: "SIGNEXTEND",
		0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT",
		0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
		0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE", 0x1b: "SHL",
		0x1c: "SHR", 0x1d: "SAR",
		0x20: "SHA3",
		0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
		0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
		0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
		0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY",
		0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
		0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
		0x43: "NUMBER", 0x44: "DIFFICULTY", 0x45: "GASLIMIT",
		0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
		0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
		0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
		0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST",
		0x80: "DUP1", 0x81: "DUP2", 0x82: "DUP3", 0x83: "DUP4",
		0x84: "DUP5", 0x85: "DUP6", 0x86: "DUP7", 0x87: "DUP8",
		0x90: "SWAP1", 0x91: "SWAP2", 0x92: "SWAP3", 0x93: "SWAP4",
		0xa0: "LOG0", 0xa1: "LOG1", 0xa2: "LOG2", 0xa3: "LOG3", 0xa4: "LOG4",
		0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN",
		0xf4: "DELEGATECALL", 0xf5: "CREATE2",
		0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
	}

	// PUSH1..PUSH32 (0x60..0x7f)
	if op >= 0x60 && op <= 0x7f {
		n := int(op - 0x5f)
		return fmt.Sprintf("PUSH%d", n), n
	}

	if name, ok := opcodes[op]; ok {
		return name, 0
	}
	return fmt.Sprintf("0x%02x", op), 0
}

func BytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

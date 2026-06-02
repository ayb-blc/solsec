// Package taint implements source-to-sink taint analysis for Solidity code.
//
// The package tracks attacker-controlled values such as calldata, msg.sender,
// msg.value, tx.origin, and miner-influenced block fields through assignments,
// interprocedural calls, storage reads/writes, and dangerous sink operations.
package taint

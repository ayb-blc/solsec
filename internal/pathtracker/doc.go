// Package pathtracker provides lightweight path-sensitive helpers for common
// Solidity security patterns without building a full control-flow graph.
//
// It focuses on localized signals that improve detector precision: early
// guards, access-controlled branches, and custom reentrancy mutexes.
package pathtracker

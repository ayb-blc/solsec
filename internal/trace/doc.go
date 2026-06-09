// Package trace provides evidence-chain models for security findings.
//
// Detectors use traces to explain why a finding was emitted, for example:
// state read -> external call -> state write. Reporters render traces to text,
// JSON, and SARIF code flows.
package trace

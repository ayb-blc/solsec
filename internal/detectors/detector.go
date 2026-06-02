package detectors

import "github.com/ayb-blc/solsec/internal/analyzer"

// Detector is an alias to the analyzer contract. Keeping a single canonical
// interface prevents subtle package-boundary mistakes where the concrete
// detectors appear not to implement the interface because the Finding type came
// from a different package path or an import cycle.
type Detector = analyzer.Detector

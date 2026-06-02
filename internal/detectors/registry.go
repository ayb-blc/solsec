package detectors

import "github.com/ayb-blc/solsec/internal/analyzer"

func DefaultDetectors() []analyzer.Detector {
	return []analyzer.Detector{
		NewReentrancyDetectorV2(),
		NewTxOriginDetector(),
		NewDelegatecallDetector(),
		NewUncheckedCallDetectorV2(),
		NewAccessControlDetector(),
		NewIntegerOverflowDetectorV2(),
	}
}

func DefaultRegistry() *analyzer.Registry {
	return analyzer.NewRegistry(DefaultDetectors()...)
}

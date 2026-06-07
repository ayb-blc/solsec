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
		NewReinitializableInitDetector(),
		NewConstructorInUpgradeableDetector(),
		NewUninitializedOwnableDetector(),
	}
}

func ExperimentalDetectors() []analyzer.Detector {
	return []analyzer.Detector{
		NewStorageGapMissingDetector(),
		NewOverrideRemovesRestrictionDetector(),
	}
}

func AllDetectors() []analyzer.Detector {
	return append(DefaultDetectors(), ExperimentalDetectors()...)
}

func DefaultRegistry() *analyzer.Registry {
	return analyzer.NewRegistry(DefaultDetectors()...)
}

func AllRegistry() *analyzer.Registry {
	return analyzer.NewRegistry(AllDetectors()...)
}

package analyzer

// Registry keeps detector construction centralized without importing concrete
// detector packages into analyzer. The CLI can use this through adapters from
// the detectors package while tests can build custom registries.
type Registry struct {
	detectors []Detector
}

func NewRegistry(detectors ...Detector) *Registry {
	return &Registry{detectors: append([]Detector(nil), detectors...)}
}

func (r *Registry) Detectors() []Detector {
	if r == nil {
		return nil
	}
	return append([]Detector(nil), r.detectors...)
}

func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.detectors))
	for _, detector := range r.detectors {
		names = append(names, detector.Name())
	}
	return names
}

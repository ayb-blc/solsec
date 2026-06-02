package detectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SolidityVersion is a small pragma model used by version-aware detectors.
type SolidityVersion struct {
	Major      int
	Minor      int
	Patch      int
	Constraint string
	IsExact    bool
}

type VersionRisk struct {
	Version      *SolidityVersion
	OverflowRisk bool
}

func ParseVersion(source string) (*SolidityVersion, error) {
	re := regexp.MustCompile(`pragma\s+solidity\s+([^;]+);`)
	m := re.FindStringSubmatch(source)
	if len(m) < 2 {
		return &SolidityVersion{Major: 0, Minor: 8, Patch: 0, Constraint: "unknown"}, nil
	}

	constraint := strings.TrimSpace(m[1])
	versionRe := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	vm := versionRe.FindStringSubmatch(constraint)
	if len(vm) < 4 {
		return nil, fmt.Errorf("could not parse solidity version constraint %q", constraint)
	}

	major, _ := strconv.Atoi(vm[1])
	minor, _ := strconv.Atoi(vm[2])
	patch, _ := strconv.Atoi(vm[3])

	return &SolidityVersion{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Constraint: constraint,
		IsExact:    !strings.ContainsAny(constraint, "^<>=~*"),
	}, nil
}

func AssessVersionRisk(source string) *VersionRisk {
	version, err := ParseVersion(source)
	if err != nil {
		return &VersionRisk{OverflowRisk: true}
	}
	return &VersionRisk{
		Version:      version,
		OverflowRisk: version.MightBeBelow08(),
	}
}

func (v *SolidityVersion) String() string {
	if v == nil {
		return "unknown"
	}
	if v.Constraint != "" && v.Constraint != "unknown" {
		return v.Constraint
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v *SolidityVersion) MightBeBelow08() bool {
	if v == nil {
		return true
	}
	if v.Major > 0 {
		return false
	}
	if v.Minor < 8 {
		return true
	}
	if strings.Contains(v.Constraint, "<0.8") || strings.Contains(v.Constraint, "< 0.8") {
		return true
	}
	return false
}

func (v *SolidityVersion) HasBuiltinOverflowProtection() bool {
	return !v.MightBeBelow08()
}

// Package vuln содержит доменные типы: компонент SBOM, находку и пропущенный компонент.
package vuln

// Component это одна зависимость из SBOM.
type Component struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
}

// Finding это одна уязвимость в одном пакете после склейки идентификаторов.
type Finding struct {
	IDs           []string // все идентификаторы: GHSA, GO, CVE и т. д.
	CVEs          []string // только CVE, по ним работают KEV и EPSS
	Package       Component
	CVSS          *float64
	EPSS          *float64
	InKEV         bool
	Malicious     bool
	FixedVersions []string
}

// Clone возвращает копию, которую можно менять, не задевая оригинал.
func (f Finding) Clone() Finding {
	c := f
	c.IDs = append([]string(nil), f.IDs...)
	c.CVEs = append([]string(nil), f.CVEs...)
	c.FixedVersions = append([]string(nil), f.FixedVersions...)
	if f.CVSS != nil {
		v := *f.CVSS
		c.CVSS = &v
	}
	if f.EPSS != nil {
		v := *f.EPSS
		c.EPSS = &v
	}
	return c
}

// CloneAll копирует список находок.
func CloneAll(fs []Finding) []Finding {
	out := make([]Finding, len(fs))
	for i, f := range fs {
		out[i] = f.Clone()
	}
	return out
}

// SkipReason объясняет, почему компонент не проверен.
type SkipReason string

const (
	NoVersion            SkipReason = "no_version"
	UnsupportedEcosystem SkipReason = "unsupported_ecosystem"
)

// Skipped это компонент, который Tool не смог проверить.
type Skipped struct {
	Component Component
	Reason    SkipReason
}

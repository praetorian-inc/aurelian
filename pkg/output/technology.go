package output

// Technology is a CPE-identifiable piece of software observed on a cloud
// resource. It is inventory, not a finding: aurelian performs no vulnerability
// lookup against it. Guard resolves the CPE to CVEs centrally.
//
// Technology deliberately does not embed model.BaseAurelianModel. It is never
// emitted as a top-level pipeline item; it only ever travels as a field on a
// resource.
type Technology struct {
	// CPE is the full CPE 2.3 formatted string. Required. A Technology with an
	// empty or unparseable CPE is dropped rather than emitted.
	CPE string `json:"cpe"`

	// Name is advisory only and may be left empty. Guard overwrites it on
	// ingest from the NVD dictionary, so populating it here is wasted effort.
	Name string `json:"name,omitempty"`

	// Source identifies the detector that fired, for weighting and debugging.
	// e.g. "rds-engine", "lambda-runtime", "ecs-image-tag", "layer-pkgdb".
	Source string `json:"source,omitempty"`

	// Evidence records how the technology was identified. Guard does not render
	// it today; it is kept because it is free and makes aurelian's own JSON
	// output debuggable.
	// e.g. "EngineVersion=15.4", "image nginx:1.25.3-alpine".
	Evidence string `json:"evidence,omitempty"`
}

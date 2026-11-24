package enrichers

import (
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/software"
)

func init() {
	// Register for exactly the types software.Detect can decode. Reading the
	// list from the decoder registry keeps the two from drifting when a
	// decoder is added.
	for _, resourceType := range software.RegisteredTypes() {
		plugin.RegisterEnricher(resourceType, enrichTechnologies)
	}
}

// enrichTechnologies populates r.Technologies from the resource's property
// bag. Detect itself is pure; the image-config read that follows it is the
// one path here that reaches the network, and it fails soft.
func enrichTechnologies(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	// Assigned, not appended: running twice must not double the field.
	r.Technologies = software.Detect(r.ResourceType, r.Properties)

	// Reaches the images a tag cannot identify: a private myorg/app built FROM
	// python:3.11 carries PYTHON_VERSION in its config, and the runtime under
	// an entrypoint — the JDK beneath Tomcat — is only visible here. It costs
	// three small requests per distinct image, no layer bytes, cached per
	// reference for the run, and it fails soft, so this still returns nil
	// unconditionally and a resource keeps whatever its tag already yielded.
	r.Technologies = dedupeTechnologies(append(r.Technologies, imageConfigTechnologies(cfg, r)...))
	return nil
}

// dedupeTechnologies keeps the first technology seen for each CPE. The tag and
// the config routinely agree, and emitting a CPE twice would double every
// finding guard derives from it. First wins, so the tag keeps provenance — it
// was observed, not recovered from an environment variable.
func dedupeTechnologies(techs []output.Technology) []output.Technology {
	if len(techs) < 2 {
		return techs
	}
	out := make([]output.Technology, 0, len(techs))
	seen := make(map[string]struct{}, len(techs))
	for _, t := range techs {
		if _, dup := seen[t.CPE]; dup {
			continue
		}
		seen[t.CPE] = struct{}{}
		out = append(out, t)
	}
	return out
}

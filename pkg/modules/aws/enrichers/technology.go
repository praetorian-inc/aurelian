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

// hydratedPaths names, per resource type, a property path that must be present
// before Detect can decode anything. CloudControl's ListResources returns a
// sparse property set for some types, and a type listed here is hydrated via
// GetResource when its path is missing.
//
// Lambda is the measured case: across every function in the harvest account the
// union of keys ListResources returned was {FunctionName, FunctionUrl,
// FunctionUrlAuthType, Role} — neither Runtime nor Code.ImageUri among them
// (pkg/software/testdata/properties/aws/FINDINGS.md). ECS is deliberately absent
// from this map: ContainerDefinitions arrives complete and inline, so hydrating
// it would buy a GetResource call per task definition and nothing else.
var hydratedPaths = map[string][]string{
	"AWS::Lambda::Function": {"Runtime"},
}

// enrichTechnologies populates r.Technologies from the resource's property bag.
//
// Detect is a pure function of (resourceType, properties) and makes no network
// call, so this enricher cannot fail; it returns nil unconditionally. The one
// call it may make is the hydration above, which is itself best-effort and
// swallows its own errors.
func enrichTechnologies(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	if path, ok := hydratedPaths[r.ResourceType]; ok {
		hydrateIfMissing(cfg, r, path...)
	}

	// Assigned, not appended: Detect is the sole author of this field, and an
	// enricher that ran twice on one resource must not double it.
	r.Technologies = software.Detect(r.ResourceType, r.Properties)
	return nil
}

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

// enrichTechnologies populates r.Technologies from the resource's property bag.
//
// It makes no API call of its own, which is what keeps it off the wrong side of
// the design's anti-goal: list-all and public-resources must not pay a
// per-resource call for version data. Every property it reads is supplied by
// the enumerator that already listed the resource, or by a type-specific
// enricher that fetches it under its own cost rationale — Lambda's image
// reference is the one such case (enrichers/lambda.go), and it is gated on
// PackageType so only image-packaged functions pay.
//
// This deliberately does *not* hydrate via CloudControl GetResource. An earlier
// revision hydrated Lambda on a missing `Runtime`, on the premise that
// ListResources was sparse. The premise was wrong twice over: Lambda in
// list-all is enumerated by the native Lambda SDK, not CloudControl
// (pkg/aws/enumeration/lambda_function_enumerator.go), so Runtime is free from
// the listing it already pays for; and `Code/ImageUri` is a *write-only*
// property in the CloudFormation schema, so GetResource can never return it at
// any price. The hydration bought one redundant value and one unobtainable one,
// for a GetResource per function on both hot paths.
//
// Detect is a pure function of (resourceType, properties) and makes no network
// call. The one thing here that can reach the network is the image-config
// read, and it is gated behind --image-configs and fails soft, so this
// enricher still returns nil unconditionally.
func enrichTechnologies(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	// Assigned, not appended: this enricher is the sole author of the field,
	// and one that ran twice on a resource must not double it.
	r.Technologies = software.Detect(r.ResourceType, r.Properties)

	// Opt-in, because this is the one path here that acquires a per-image
	// registry call. What it buys is the images a tag cannot identify: a
	// private myorg/app built FROM python:3.11 carries PYTHON_VERSION in its
	// config, and the runtime under an entrypoint — the JDK beneath Tomcat —
	// is only ever visible here.
	if cfg.ScanImageConfigs {
		r.Technologies = dedupeTechnologies(append(r.Technologies, imageConfigTechnologies(cfg, r)...))
	}
	return nil
}

// dedupeTechnologies keeps the first technology seen for each CPE.
//
// The tag and the config routinely agree — nginx:1.25.5 yields f5:nginx:1.25.5
// from both — and emitting it twice would double every finding guard derives
// from it. First wins, so a CPE the tag resolved keeps the tag's provenance,
// which is the more precise claim: it was observed, not recovered from an
// environment variable.
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

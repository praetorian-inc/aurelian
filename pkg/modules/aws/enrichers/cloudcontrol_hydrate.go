package enrichers

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	// Direct-read ingress types whose evaluators read a single CloudControl
	// property. CloudControl ListResources returns a sparse property set for
	// these, so the property is hydrated via GetResource here.
	plugin.RegisterEnricher("AWS::Transfer::Server", enrichViaHydrate)
	plugin.RegisterEnricher("AWS::AppSync::GraphQLApi", enrichViaHydrate)
	plugin.RegisterEnricher("AWS::GlobalAccelerator::Accelerator", enrichViaHydrate)
	// AWS::ElasticBeanstalk::Environment uses a dedicated enricher (beanstalk.go)
	// that hydrates and also rewrites the ARN from ApplicationName + EnvironmentName.
	// REST APIs also run a method-fetch enricher (apigateway.go); hydrate adds
	// EndpointConfiguration + Policy, which the evaluator uses to skip PRIVATE
	// endpoints and downgrade resource-policy-gated APIs.
	plugin.RegisterEnricher("AWS::ApiGateway::RestApi", enrichViaHydrate)
}

func enrichViaHydrate(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateFromCloudControl(cfg, r)
	return nil
}

// hydrateIfMissing runs hydrateFromCloudControl only when the value at the given
// nested property path is absent. This guards against the sparse-ListResources
// case where a container property exists but the specific leaf the evaluator
// reads is missing — checking only the top-level container would skip the
// needed hydration.
func hydrateIfMissing(cfg plugin.EnricherConfig, r *output.AWSResource, path ...string) {
	if nestedValuePresent(r.Properties, path...) {
		return
	}
	hydrateFromCloudControl(cfg, r)
}

// nestedValuePresent reports whether a value exists at the given path, descending
// through map[string]any nodes.
func nestedValuePresent(props map[string]any, path ...string) bool {
	var cur any = props
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		v, ok := m[key]
		if !ok {
			return false
		}
		cur = v
	}
	return true
}

// mergeMissing fills keys present in src but absent in dst. When a key exists in
// both and both values are maps, it recurses to fill missing leaves without
// overwriting existing scalar/list values. This lets a full GetResource payload
// complete a partial container returned by ListResources.
func mergeMissing(dst, src map[string]any) {
	for k, sv := range src {
		dv, exists := dst[k]
		if !exists {
			dst[k] = sv
			continue
		}
		dm, dok := dv.(map[string]any)
		sm, sok := sv.(map[string]any)
		if dok && sok {
			mergeMissing(dm, sm)
		}
	}
}

// hydrateFromCloudControl fetches the full CloudControl property set for a
// resource via GetResource and merges any properties missing from the sparse
// ListResources payload. Existing properties are never overwritten. Failures
// are logged and swallowed: enrichment is best-effort, and a resource that
// cannot be hydrated simply evaluates against whatever properties it already
// has.
func hydrateFromCloudControl(cfg plugin.EnricherConfig, r *output.AWSResource) {
	if r.ResourceID == "" {
		return
	}
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	client := cloudcontrol.NewFromConfig(cfg.AWSConfig)
	out, err := client.GetResource(ctx, &cloudcontrol.GetResourceInput{
		TypeName:   &r.ResourceType,
		Identifier: &r.ResourceID,
	})
	if err != nil {
		slog.Warn("cloudcontrol hydrate failed",
			"type", r.ResourceType, "resource", r.ResourceID, "error", err)
		return
	}
	if out.ResourceDescription == nil || out.ResourceDescription.Properties == nil {
		return
	}
	var full map[string]any
	if err := json.Unmarshal([]byte(*out.ResourceDescription.Properties), &full); err != nil {
		return
	}
	if r.Properties == nil {
		r.Properties = make(map[string]any)
	}
	mergeMissing(r.Properties, full)
}

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
	plugin.RegisterEnricher("AWS::ElasticBeanstalk::Environment", enrichViaHydrate)
	// REST APIs also run a method-fetch enricher (apigateway.go); hydrate adds
	// EndpointConfiguration + Policy, which the evaluator uses to skip PRIVATE
	// endpoints and downgrade resource-policy-gated APIs.
	plugin.RegisterEnricher("AWS::ApiGateway::RestApi", enrichViaHydrate)
}

func enrichViaHydrate(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	hydrateFromCloudControl(cfg, r)
	return nil
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
	for k, v := range full {
		if _, exists := r.Properties[k]; !exists {
			r.Properties[k] = v
		}
	}
}

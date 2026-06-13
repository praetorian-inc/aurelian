package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// GlueDevEndpointEnumerator enumerates Glue development endpoints using the native
// Glue SDK. Dev endpoints have no resource policy; they are emitted so the
// resource_service_role enricher can link an endpoint to the IAM role it RUNS AS
// (DevEndpoint.RoleArn) via a (DevEndpoint)-[:HAS_ROLE]->(Role) edge, which the glue
// privesc methods re-point their CAN_PRIVESC edge at.
//
// GetDevEndpoints returns full endpoint definitions (including RoleArn) directly, so
// no per-endpoint describe is needed.
type GlueDevEndpointEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewGlueDevEndpointEnumerator creates a GlueDevEndpointEnumerator that uses the native Glue SDK.
func NewGlueDevEndpointEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *GlueDevEndpointEnumerator {
	return &GlueDevEndpointEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Glue dev endpoints.
func (l *GlueDevEndpointEnumerator) ResourceType() string {
	return "AWS::Glue::DevEndpoint"
}

// EnumerateAll enumerates all Glue dev endpoints owned by the account across configured regions.
func (l *GlueDevEndpointEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listDevEndpointsInRegion(region, accountID, out)
	})
}

func (l *GlueDevEndpointEnumerator) listDevEndpointsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Glue client for %s: %w", region, err)
	}
	client := glue.NewFromConfig(*cfg)

	paginator := glue.NewGetDevEndpointsPaginator(client, &glue.GetDevEndpointsInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "glue", "GetDevEndpoints", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("get dev endpoints in %s: %w", region, err)
		}
		for _, endpoint := range page.DevEndpoints {
			out.Send(buildGlueDevEndpointResource(endpoint, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildGlueDevEndpointResource(endpoint gluetypes.DevEndpoint, accountID, region string) output.AWSResource {
	name := aws.ToString(endpoint.EndpointName)

	// Glue dev endpoints carry no ARN field; synthesize the standard ARN so the node keys cleanly.
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:devEndpoint/%s", region, accountID, name)

	return output.AWSResource{
		ResourceType: "AWS::Glue::DevEndpoint",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"EndpointName": name,
			// RoleArn is the role the endpoint assumes; resource_service_role.yaml
			// substring-matches this quoted ARN value inside the flattened `properties` JSON
			// string to create the (DevEndpoint)-[:HAS_ROLE]->(Role) edge.
			"RoleArn": aws.ToString(endpoint.RoleArn),
		},
	}
}

package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// cognitoListPageSize is the per-call ListIdentityPools page size (MaxResults is required
// by the API and capped at 60).
const cognitoListPageSize = 60

// CognitoIdentityPoolEnumerator enumerates Cognito identity pools using the native
// cognito-identity SDK. Identity pools have no resource policy; they are emitted so the
// cognito_set_identity_pool_roles privesc method can (a) re-point its CAN_PRIVESC edge at
// the IAM role bound to the pool via a (IdentityPool)-[:HAS_ROLE]->(Role) edge, and
// (b) relax its GetId/GetCredentials requirement when the pool allows UNAUTHENTICATED
// identities (those APIs need no IAM permission for an unauth-enabled pool).
//
// ListIdentityPools returns only id/name, so each pool is described per-id via
// DescribeIdentityPool (AllowUnauthenticatedIdentities) and GetIdentityPoolRoles
// (authenticated / unauthenticated role ARNs).
type CognitoIdentityPoolEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewCognitoIdentityPoolEnumerator creates a CognitoIdentityPoolEnumerator that uses the native cognito-identity SDK.
func NewCognitoIdentityPoolEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *CognitoIdentityPoolEnumerator {
	return &CognitoIdentityPoolEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Cognito identity pools.
func (l *CognitoIdentityPoolEnumerator) ResourceType() string {
	return "AWS::Cognito::IdentityPool"
}

// EnumerateAll enumerates all Cognito identity pools owned by the account across configured regions.
func (l *CognitoIdentityPoolEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listIdentityPoolsInRegion(region, accountID, out)
	})
}

func (l *CognitoIdentityPoolEnumerator) listIdentityPoolsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Cognito Identity client for %s: %w", region, err)
	}
	client := cognitoidentity.NewFromConfig(*cfg)

	var skipped []SkippedOp
	var nextToken *string
	for {
		page, err := client.ListIdentityPools(context.Background(), &cognitoidentity.ListIdentityPoolsInput{
			MaxResults: aws.Int32(cognitoListPageSize),
			NextToken:  nextToken,
		})
		if err != nil {
			if op := ClassifySkippable(err, "cognito-identity", "ListIdentityPools", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list identity pools in %s: %w", region, err)
		}
		for _, summary := range page.IdentityPools {
			id := aws.ToString(summary.IdentityPoolId)
			if id == "" {
				continue
			}
			resource, err := l.describePool(client, id, aws.ToString(summary.IdentityPoolName), region, accountID, &skipped)
			if err != nil {
				return err
			}
			if resource != nil {
				out.Send(*resource)
			}
		}
		if aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// describePool resolves a pool's AllowUnauthenticatedIdentities flag and bound role ARNs.
// A skipped describe is recorded and yields a nil resource so one inaccessible pool does
// not fail the whole region.
func (l *CognitoIdentityPoolEnumerator) describePool(client *cognitoidentity.Client, poolID, poolName, region, accountID string, skipped *[]SkippedOp) (*output.AWSResource, error) {
	detail, err := client.DescribeIdentityPool(context.Background(), &cognitoidentity.DescribeIdentityPoolInput{
		IdentityPoolId: aws.String(poolID),
	})
	if err != nil {
		if op := ClassifySkippable(err, "cognito-identity", "DescribeIdentityPool", region); op != nil {
			*skipped = append(*skipped, *op)
			return nil, nil
		}
		return nil, fmt.Errorf("describe identity pool %s in %s: %w", poolID, region, err)
	}

	roles, err := client.GetIdentityPoolRoles(context.Background(), &cognitoidentity.GetIdentityPoolRolesInput{
		IdentityPoolId: aws.String(poolID),
	})
	if err != nil {
		if op := ClassifySkippable(err, "cognito-identity", "GetIdentityPoolRoles", region); op != nil {
			*skipped = append(*skipped, *op)
			return nil, nil
		}
		return nil, fmt.Errorf("get identity pool roles for %s in %s: %w", poolID, region, err)
	}

	resource := buildIdentityPoolResource(poolID, poolName, detail.AllowUnauthenticatedIdentities, roles.Roles, accountID, region)
	return &resource, nil
}

func buildIdentityPoolResource(poolID, poolName string, allowUnauth bool, boundRoles map[string]string, accountID, region string) output.AWSResource {
	props := map[string]any{
		"IdentityPoolId":   poolID,
		"IdentityPoolName": poolName,
		// AllowUnauthenticatedIdentities is promoted to a top-level node prop so
		// cognito_set_identity_pool_roles can relax its GetId/GetCredentials guard for
		// pools reachable without authentication.
		"AllowUnauthenticatedIdentities": allowUnauth,
	}
	// The bound role ARNs (authenticated / unauthenticated) appear as quoted values in the
	// flattened properties JSON; resource_service_role.yaml substring-matches them to create
	// the (IdentityPool)-[:HAS_ROLE]->(Role) edges.
	for slot, roleArn := range boundRoles {
		if roleArn != "" {
			props[slot+"Role"] = roleArn
		}
	}

	return output.AWSResource{
		ResourceType: "AWS::Cognito::IdentityPool",
		ResourceID:   poolID,
		ARN:          fmt.Sprintf("arn:aws:cognito-identity:%s:%s:identitypool/%s", region, accountID, poolID),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  poolName,
		Properties:   props,
	}
}

package enumeration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// RAMResourceShareEnumerator enumerates AWS RAM resource shares owned by the
// account (ResourceOwner=SELF) using the native RAM SDK. CloudControl's
// AWS::RAM::ResourceShare read/list handlers hold only ram:GetResourceShares,
// so they cannot populate the associated principals or resources; this
// enumerator calls GetResourceShareAssociations directly to attach both.
//
// The security-relevant signal is AllowExternalPrincipals (whether the share
// may be associated with accounts outside the owner's AWS Organization);
// downstream evaluation cross-references the associated principals against org
// membership. Consumer-side shares (ResourceOwner=OTHER-ACCOUNTS) are out of
// scope for this enumerator.
type RAMResourceShareEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewRAMResourceShareEnumerator creates a RAMResourceShareEnumerator that uses the native RAM SDK.
func NewRAMResourceShareEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *RAMResourceShareEnumerator {
	return &RAMResourceShareEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for RAM resource shares.
func (l *RAMResourceShareEnumerator) ResourceType() string {
	return "AWS::RAM::ResourceShare"
}

// buildResourceShareResource maps a RAM ResourceShare plus its resolved
// principal and resource associations to an output.AWSResource. Pure function
// (no SDK calls) so it is unit-testable. accountID is the caller's account,
// used only when the share omits OwningAccountId.
func buildResourceShareResource(share ramtypes.ResourceShare, principals, resourceArns []string, accountID, region string) output.AWSResource {
	arn := aws.ToString(share.ResourceShareArn)
	name := aws.ToString(share.Name)

	owner := aws.ToString(share.OwningAccountId)
	if owner == "" {
		owner = accountID
	}

	if principals == nil {
		principals = []string{}
	}
	if resourceArns == nil {
		resourceArns = []string{}
	}

	return output.AWSResource{
		ResourceType: "AWS::RAM::ResourceShare",
		ResourceID:   arn,
		ARN:          arn,
		AccountRef:   owner,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"Name":                    name,
			"AllowExternalPrincipals": aws.ToBool(share.AllowExternalPrincipals),
			"Status":                  string(share.Status),
			"FeatureSet":              string(share.FeatureSet),
			"OwningAccountId":         owner,
			"Principals":              principals,
			"ResourceArns":            resourceArns,
		},
	}
}

// EnumerateAll enumerates all RAM resource shares owned by the account
// (ResourceOwner=SELF) across configured regions.
func (l *RAMResourceShareEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listSharesInRegion(region, accountID, out)
	})
}

func (l *RAMResourceShareEnumerator) listSharesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create RAM client for %s: %w", region, err)
	}
	client := ram.NewFromConfig(*cfg)

	paginator := ram.NewGetResourceSharesPaginator(client, &ram.GetResourceSharesInput{
		ResourceOwner: ramtypes.ResourceOwnerSelf,
	})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ram", "GetResourceShares", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("get resource shares in %s: %w", region, err)
		}
		for _, share := range page.ResourceShares {
			arn := aws.ToString(share.ResourceShareArn)
			if arn == "" {
				continue
			}
			principals := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypePrincipal, region, &skipped)
			resources := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypeResource, region, &skipped)
			out.Send(buildResourceShareResource(share, principals, resources, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// associatedEntities returns the AssociatedEntity values for a share for the
// given association type (PRINCIPAL → account/org/OU/role ARNs; RESOURCE →
// resource ARNs). Skippable errors are appended to skipped and an empty slice
// is returned so the share is still emitted with whatever else resolved.
func (l *RAMResourceShareEnumerator) associatedEntities(client *ram.Client, shareArn string, assocType ramtypes.ResourceShareAssociationType, region string, skipped *[]SkippedOp) []string {
	paginator := ram.NewGetResourceShareAssociationsPaginator(client, &ram.GetResourceShareAssociationsInput{
		AssociationType:   assocType,
		ResourceShareArns: []string{shareArn},
	})
	var entities []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ram", "GetResourceShareAssociations", region); op != nil {
				*skipped = append(*skipped, *op)
				return entities
			}
			slog.Warn("non-skippable GetResourceShareAssociations error, emitting partial associations",
				"share", shareArn, "type", string(assocType), "region", region, "error", err)
			return entities
		}
		for _, assoc := range page.ResourceShareAssociations {
			if e := aws.ToString(assoc.AssociatedEntity); e != "" {
				entities = append(entities, e)
			}
		}
	}
	return entities
}

// EnumerateByARN fetches a single RAM resource share by ARN (ResourceOwner=SELF).
func (l *RAMResourceShareEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	if !strings.HasPrefix(parsed.Resource, "resource-share/") {
		return fmt.Errorf("not a RAM resource-share ARN: %q", arn)
	}
	if parsed.Region == "" {
		return fmt.Errorf("RAM resource share ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create RAM client for %s: %w", parsed.Region, err)
	}
	client := ram.NewFromConfig(*cfg)

	resp, err := client.GetResourceShares(context.Background(), &ram.GetResourceSharesInput{
		ResourceOwner:     ramtypes.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	})
	if err != nil {
		if op := ClassifySkippable(err, "ram", "GetResourceShares", parsed.Region); op != nil {
			l.skipReport.RecordBatch([]SkippedOp{*op})
			return nil
		}
		return fmt.Errorf("get resource share %s: %w", arn, err)
	}
	if len(resp.ResourceShares) == 0 {
		return fmt.Errorf("resource share %s not found (owner=SELF) in %s", arn, parsed.Region)
	}

	var skipped []SkippedOp
	share := resp.ResourceShares[0]
	principals := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypePrincipal, parsed.Region, &skipped)
	resources := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypeResource, parsed.Region, &skipped)
	l.skipReport.RecordBatch(skipped)

	out.Send(buildResourceShareResource(share, principals, resources, parsed.AccountID, parsed.Region))
	return nil
}

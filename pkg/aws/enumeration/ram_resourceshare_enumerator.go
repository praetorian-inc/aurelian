package enumeration

import (
	"context"
	"fmt"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
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

	// Account ID is resolved inside each region's own (already-validated) config
	// rather than from a single prerequisite region, so one disabled region does
	// not abort the whole enumeration. It is only used as a fallback when a share
	// omits OwningAccountId.
	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listSharesInRegion(region, out)
	})
}

func (l *RAMResourceShareEnumerator) listSharesInRegion(region string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create RAM client for %s: %w", region, err)
	}

	var skipped []SkippedOp
	defer func() { l.skipReport.RecordBatch(skipped) }()

	accountID, err := awshelpers.GetAccountId(*cfg)
	if err != nil {
		if op := ClassifySkippable(err, "sts", "GetCallerIdentity", region); op != nil {
			skipped = append(skipped, *op)
			return nil
		}
		return fmt.Errorf("resolve account for %s: %w", region, err)
	}

	client := ram.NewFromConfig(*cfg)

	paginator := ram.NewGetResourceSharesPaginator(client, &ram.GetResourceSharesInput{
		ResourceOwner:       ramtypes.ResourceOwnerSelf,
		ResourceShareStatus: ramtypes.ResourceShareStatusActive,
	})
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
			principals, err := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypePrincipal, region, &skipped)
			if err != nil {
				return err
			}
			resources, err := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypeResource, region, &skipped)
			if err != nil {
				return err
			}
			out.Send(buildResourceShareResource(share, principals, resources, accountID, region))
		}
	}
	return nil
}

// associatedEntities returns the AssociatedEntity values for a share for the
// given association type (PRINCIPAL → account/org/OU/role ARNs; RESOURCE →
// resource ARNs). A skippable error (access denied, region unsupported) is
// appended to skipped and the entities resolved so far are returned, so the
// share is still emitted best-effort. A non-skippable error is returned to the
// caller so a genuine failure aborts the region rather than silently emitting a
// share with a misleading (partial) principals/resources set.
func (l *RAMResourceShareEnumerator) associatedEntities(client *ram.Client, shareArn string, assocType ramtypes.ResourceShareAssociationType, region string, skipped *[]SkippedOp) ([]string, error) {
	paginator := ram.NewGetResourceShareAssociationsPaginator(client, &ram.GetResourceShareAssociationsInput{
		AssociationType:   assocType,
		AssociationStatus: ramtypes.ResourceShareAssociationStatusAssociated,
		ResourceShareArns: []string{shareArn},
	})
	var entities []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ram", "GetResourceShareAssociations", region); op != nil {
				*skipped = append(*skipped, *op)
				return entities, nil
			}
			return nil, fmt.Errorf("get %s associations for %s in %s: %w", assocType, shareArn, region, err)
		}
		for _, assoc := range page.ResourceShareAssociations {
			if e := aws.ToString(assoc.AssociatedEntity); e != "" {
				entities = append(entities, e)
			}
		}
	}
	return entities, nil
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
		ResourceOwner:       ramtypes.ResourceOwnerSelf,
		ResourceShareStatus: ramtypes.ResourceShareStatusActive,
		ResourceShareArns:   []string{arn},
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
	defer func() { l.skipReport.RecordBatch(skipped) }()

	share := resp.ResourceShares[0]
	principals, err := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypePrincipal, parsed.Region, &skipped)
	if err != nil {
		return err
	}
	resources, err := l.associatedEntities(client, arn, ramtypes.ResourceShareAssociationTypeResource, parsed.Region, &skipped)
	if err != nil {
		return err
	}

	out.Send(buildResourceShareResource(share, principals, resources, parsed.AccountID, parsed.Region))
	return nil
}

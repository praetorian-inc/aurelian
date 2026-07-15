package enumeration

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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

package helpers

import (
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// CloudControlToERD converts a CloudControl ResourceDescription to an EnrichedResourceDescription.
// Handles global service region normalization and SDK pointer dereferencing.
func CloudControlToERD(desc cctypes.ResourceDescription, resourceType, accountID, region string) *types.EnrichedResourceDescription {
	if awshelpers.IsGlobalService(resourceType) {
		region = ""
	}

	erd := types.NewEnrichedResourceDescription(
		*desc.Identifier,
		resourceType,
		region,
		accountID,
		*desc.Properties,
	)

	return &erd
}

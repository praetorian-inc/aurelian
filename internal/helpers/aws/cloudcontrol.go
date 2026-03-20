package helpers

import (
	"encoding/json"

	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// CloudControlToAWSResource converts a CloudControl ResourceDescription
// directly to an AWSResource without an intermediate ERD.
func CloudControlToAWSResource(desc cctypes.ResourceDescription, resourceType, accountID, region string) output.AWSResource {
	if IsGlobalService(resourceType) {
		region = ""
	}

	identifier := *desc.Identifier
	a := types.BuildResourceARN(identifier, resourceType, region, accountID)

	// SQS special case: extract queue name from the parsed ARN
	if resourceType == "AWS::SQS::Queue" && a.Resource != "" {
		identifier = a.Resource
	}

	resource := output.AWSResource{
		ResourceType: resourceType,
		ResourceID:   identifier,
		ARN:          a.String(),
		AccountRef:   accountID,
		Region:       region,
	}

	var props map[string]any
	if err := json.Unmarshal([]byte(*desc.Properties), &props); err == nil {
		resource.Properties = props
	} else {
		resource.Properties = map[string]any{"raw_properties": *desc.Properties}
	}

	return resource
}

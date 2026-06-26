package helpers

import (
	"encoding/json"
	"log/slog"

	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// CloudControlToAWSResource converts a CloudControl ResourceDescription
// directly to an AWSResource without an intermediate ERD.
//
// It returns ok=false when the description cannot yield a valid resource. The
// only such case is a nil Identifier: the Cloud Control API contract guarantees
// every ResourceDescription carries a primary identifier, so a nil one is a
// malformed response. Callers must skip emitting the resource when ok is false
// rather than forwarding a phantom zero-value resource into the pipeline.
func CloudControlToAWSResource(desc cctypes.ResourceDescription, resourceType, accountID, region string) (output.AWSResource, bool) {
	if IsGlobalService(resourceType) {
		region = ""
	}

	if desc.Identifier == nil {
		slog.Warn("cloudcontrol: ResourceDescription has nil Identifier, skipping",
			"resourceType", resourceType, "accountID", accountID, "region", region)
		return output.AWSResource{}, false
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

	if desc.Properties == nil {
		resource.Properties = map[string]any{}
		return resource, true
	}
	var props map[string]any
	if err := json.Unmarshal([]byte(*desc.Properties), &props); err == nil {
		resource.Properties = props
	} else {
		resource.Properties = map[string]any{"raw_properties": *desc.Properties}
	}

	return resource, true
}

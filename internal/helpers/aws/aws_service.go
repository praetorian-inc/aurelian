package helpers

import (
	"strings"
)

var GlobalServices = []string{
	"AWS::IAM::",
	"AWS::CloudFront::",
	"AWS::Route53::",
	"AWS::Organizations::",
	"AWS::ECR::PublicRepository",
}

func IsGlobalService(resourceType string) bool {
	for _, prefix := range GlobalServices {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

// RegionForService resolves the region to use when building an AWS config for a
// resource. Global services carry no meaningful region on the resource itself:
// CloudControlToAWSResource stamps Region:"" for them. That empty string is not a
// valid AWS region, so passing it to NewAWSConfig triggers the empty-region
// warning. Their control planes all live in us-east-1, so resolve to that
// explicitly. Regional resources are returned unchanged — including any that
// arrive with a genuinely empty region, which is a real bug and should keep
// triggering the NewAWSConfig warning rather than being silently defaulted.
func RegionForService(resourceType, resourceRegion string) string {
	if resourceRegion == "" && IsGlobalService(resourceType) {
		return "us-east-1"
	}
	return resourceRegion
}

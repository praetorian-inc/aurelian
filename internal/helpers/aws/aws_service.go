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
// CloudControlToAWSResource stamps Region:"" for them and the IAM enumerator
// stamps the literal "global". Neither is a valid AWS region, so passing them
// to NewAWSConfig either triggers the empty-region warning or hands the SDK a
// bogus region. Their control planes all live in us-east-1, so resolve to that
// explicitly. Regional resources (including those with a genuinely empty region,
// which is a real bug worth surfacing) are returned unchanged.
func RegionForService(resourceType, resourceRegion string) string {
	if resourceRegion == "" || resourceRegion == "global" {
		if IsGlobalService(resourceType) {
			return "us-east-1"
		}
	}
	return resourceRegion
}

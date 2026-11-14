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
	"AWS::GlobalAccelerator::",
}

// globalServiceRegions overrides the default control-plane region for global
// services that are not served from us-east-1. Global Accelerator's API is
// reachable only in us-west-2.
var globalServiceRegions = map[string]string{
	"AWS::GlobalAccelerator::": "us-west-2",
}

// GlobalServiceControlPlaneRegion returns the region hosting a global service's
// control plane, and whether the resource type is global at all. Callers that
// must issue an API call for a resource whose ARN carries no region use this
// instead of assuming us-east-1.
func GlobalServiceControlPlaneRegion(resourceType string) (string, bool) {
	if !IsGlobalService(resourceType) {
		return "", false
	}

	for prefix, region := range globalServiceRegions {
		if strings.HasPrefix(resourceType, prefix) {
			return region, true
		}
	}

	return "us-east-1", true
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
	if resourceRegion == "" {
		if region, ok := GlobalServiceControlPlaneRegion(resourceType); ok {
			return region
		}
	}
	return resourceRegion
}

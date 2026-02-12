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

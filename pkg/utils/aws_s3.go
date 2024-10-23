package utils

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/nebula/internal/logs"
)

func S3BucketPABConfigFullyBlocks(config *s3types.PublicAccessBlockConfiguration) bool {
	return *config.BlockPublicAcls &&
		*config.IgnorePublicAcls &&
		*config.BlockPublicPolicy &&
		*config.RestrictPublicBuckets
}

func S3BucketACLPublic(aclOutput *s3.GetBucketAclOutput) string {
	outString := "\"BucketACL\":{\"Grants\":["
	for _, grant := range aclOutput.Grants {
		if grant.Grantee.Type == "Group" &&
			(*grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" ||
				*grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") {
			if grant.Permission == "READ" || grant.Permission == "FULL_CONTROL" {
				outString = outString + fmt.Sprintf("{\"Grantee\":{\"ID\":\"%s\",\"Type\":%s},\"Permission\":\"%s\"},", *grant.Grantee.URI, grant.Grantee.Type, grant.Permission)
			}
		}
	}

	if outString == "\"BucketACL\":{\"Grants\":[" {
		outString = "\"BucketACL\":null"
	} else {
		outString = strings.TrimSuffix(outString, ",")
		outString = outString + "]}"
	}
	return outString
}

func S3BucketPolicyPublic(policyOutput string) string {
	outString := "\"BucketPolicy\":{\"Statement\":["

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyOutput), &policyDoc); err != nil {
		logs.ConsoleLogger().Error("Could not parse bucket access policy, error: " + err.Error())
	} else {
		statements, ok := policyDoc["Statement"].([]interface{})
		if ok {
			for _, stmt := range statements {
				statement, ok := stmt.(map[string]interface{})
				if !ok {
					continue
				}

				principal, ok := statement["Principal"]
				if !ok {
					continue
				}

				effect, ok := statement["Effect"]
				if !ok {
					continue
				}

				action, ok := statement["Action"]
				if !ok {
					continue
				}

				resource, ok := statement["Resource"]
				if !ok {
					continue
				}

				var resourceStr string
				switch resourceValue := resource.(type) {
				case string:
					resourceStr = "\"" + resourceValue + "\""
				case []interface{}:
					resourceStr = "["
					for _, arn := range resourceValue {
						if arnStr, ok := arn.(string); ok {
							resourceStr = resourceStr + fmt.Sprintf("\"%s\",", arnStr)
						}
					}
					resourceStr = strings.TrimSuffix(resourceStr, ",")
					resourceStr = resourceStr + "]"
				}

				switch principalValue := principal.(type) {
				case string:
					if (strings.Contains(principalValue, "*") || strings.Contains(principalValue, "root")) || strings.Contains(principalValue, "CloudFront Origin Access Identity") {
						if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
							actionStr := action.(string)
							resourceStr := resource.(string)

							outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":\"%s\",\"Action\":\"%s\",\"Resource\":%s},", effectStr, principalValue, actionStr, resourceStr)
						}
					}

				case map[string]interface{}:
					for _, p := range principalValue {
						switch pValue := p.(type) {
						// Principal is a direct string
						case string:
							if (strings.Contains(pValue, "*") || strings.Contains(pValue, "root")) || strings.Contains(pValue, "CloudFront Origin Access Identity") {
								if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
									actionStr := action.(string)

									outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":\"%s\",\"Action\":\"%s\",\"Resource\":%s},", effectStr, pValue, actionStr, resourceStr)
								}
							}
						// Principal is an array of ARNs
						case []interface{}:
							principalStr := "["
							for _, arn := range pValue {
								if arnStr, ok := arn.(string); ok {
									principalStr = principalStr + fmt.Sprintf("\"%s\",", arnStr)
								}
							}
							principalStr = strings.TrimSuffix(principalStr, ",")
							principalStr = principalStr + "]"

							if strings.Contains(principalStr, "*") || strings.Contains(principalStr, "root") || strings.Contains(principalStr, "CloudFront Origin Access Identity") {
								if effectStr, ok := effect.(string); ok && effectStr == "Allow" {
									actionStr := action.(string)

									outString = outString + fmt.Sprintf("{\"Effect\":\"%s\",\"Principal\":%s,\"Action\":\"%s\",\"Resource\":%s},", effectStr, principalStr, actionStr, resourceStr)
								}
							}
						}
					}
				}
			}
		}
	}
	if outString == "\"BucketPolicy\":{\"Statement\":[" {
		outString = "\"BucketPolicy\":null"
	} else {
		outString = strings.TrimSuffix(outString, ",")
		outString = outString + "]}"
	}
	return outString
}

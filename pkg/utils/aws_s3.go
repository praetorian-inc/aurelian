package utils

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

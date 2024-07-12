package options

import (
	"regexp"
)

var AwsAccessKeyIdOpt = Option{
	Name:        "access-key-id",
	Description: "AWS access key ID",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"),
}

var AwsAccountIdOpt = Option{
	Name:        "account-id",
	Description: "AWS account ID",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("[0-9]{12}"),
}

var AwsRegionOpt = Option{
	Name:        "region",
	Description: "AWS region",
	Required:    true,
	Type:        String,
	Value:       "us-east-1",
}

var AwsRegionsOpt = Option{
	Name:        "regions",
	Description: "Comma separated list of AWS regions",
	Required:    true,
	Type:        String,
	Value:       "",
}

var AwsResourceTypeOpt = Option{
	Name:        "resource-type",
	Description: "AWS Cloud Control resource type",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|ALL)$"),
}

var AwsResourceIdOpt = Option{
	Name:        "resource-id",
	Description: "AWS Cloud Control resource identifier",
	Required:    true,
	Type:        String,
	Value:       "",
}

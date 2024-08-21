package options

import (
	"regexp"
	"strings"
)

var AwsAccessKeyIdOpt = Option{
	Name:        "access-key-id",
	Short:       "k",
	Description: "AWS access key ID",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"),
}

var AwsAccountIdOpt = Option{
	Name:        "account-id",
	Short:       "i",
	Description: "AWS account ID",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("[0-9]{12}"),
}

var AwsRegionOpt = Option{
	Name:        "region",
	Short:       "r",
	Description: "AWS region",
	Required:    true,
	Type:        String,
	Value:       "us-east-1",
}

var AwsRegionsOpt = Option{
	Name:        "regions",
	Short:       "r",
	Description: "Comma separated list of AWS regions",
	Required:    true,
	Type:        String,
	Value:       "",
}

var AwsResourceTypeOpt = Option{
	Name:        "resource-type",
	Short:       "t",
	Description: "AWS Cloud Control resource type",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|ALL)$"),
}

var findsecretsTypes = []string{"cloudformation", "ecs", "ec2", "lambda", "ssm", "ALL"}
var AwsFindSecretsResourceType = Option{
	Name:        "secret-resource-types",
	Short:       "t",
	Description: "Comma separated list of AWS services. Currently supported types: " + strings.Join(findsecretsTypes, ", "),
	Required:    true,
	Type:        String,
	Value:       "",
	ValueList:   findsecretsTypes,
}

var AwsResourceIdOpt = Option{
	Name:        "resource-id",
	Short:       "i",
	Description: "AWS Cloud Control resource identifier",
	Required:    true,
	Type:        String,
	Value:       "",
}

var AwsResourceNameOpt = Option{
	Name:        "name",
	Short:       "n",
	Description: "AWS resource name",
	Required:    true,
	Type:        String,
	Value:       "",
}

var AwsSummaryServicesOpt = Option{
	Name:        "summary",
	Short:       "s",
	Description: "Use the cost explorer API to get a summary of services",
	Required:    false,
	Type:        Bool,
	Value:       "",
}

var AwsActionOpt = Option{
	Name:        "action",
	Short:       "a",
	Description: "AWS IAM action",
	Required:    true,
	Type:        String,
	Value:       "",
}

var AwsProfileOpt = Option{
	Name:        "profile",
	Description: "AWS shared credentials profile",
	Required:    false,
	Type:        String,
	Value:       "",
}

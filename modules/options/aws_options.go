package options

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/types"
)

var AwsAccessKeyIdOpt = types.Option{
	Name:        "access-key-id",
	Short:       "k",
	Description: "AWS access key ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"),
}

var AwsAccountIdOpt = types.Option{
	Name:        "account-id",
	Short:       "i",
	Description: "AWS account ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("[0-9]{12}"),
}

var AwsRegionOpt = types.Option{
	Name:        "region",
	Short:       "r",
	Description: "AWS region",
	Required:    true,
	Type:        types.String,
	Value:       "us-east-1",
}

var AwsRegionsOpt = types.Option{
	Name:        "regions",
	Short:       "r",
	Description: "Comma separated list of AWS regions. Can be 'all' for all regions.",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceTypeOpt = types.Option{
	Name:        "resource-type",
	Short:       "t",
	Description: "AWS Cloud Control resource type",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|ALL)$"),
}

var findsecretsTypes = []string{"cloudformation", "ecs", "ec2", "lambda", "ssm", "stepfunctions", "ALL"}
var AwsFindSecretsResourceType = types.Option{
	Name:        "secret-resource-types",
	Short:       "t",
	Description: "Comma separated list of AWS services. Currently supported types: " + strings.Join(findsecretsTypes, ", "),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueList:   findsecretsTypes,
}

var AwsResourceIdOpt = types.Option{
	Name:        "resource-id",
	Short:       "i",
	Description: "AWS Cloud Control resource identifier",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceNameOpt = types.Option{
	Name:        "name",
	Short:       "n",
	Description: "AWS resource name",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsSummaryServicesOpt = types.Option{
	Name:        "summary",
	Short:       "s",
	Description: "Use the cost explorer API to get a summary of services",
	Required:    false,
	Type:        types.Bool,
	Value:       "",
}

var AwsActionOpt = types.Option{
	Name:        "action",
	Short:       "a",
	Description: "AWS IAM action",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsProfileOpt = types.Option{
	Name:        "profile",
	Short:       "p",
	Description: "AWS shared credentials profile",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsProfileListOpt = types.Option{
	Name:        "profile-list",
	Short:       "l",
	Description: "List of AWS shared credentials profiles",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsScanTypeOpt = types.Option{
	Name:        "scan-type",
	Short:       "s",
	Description: "Scan type - 'full' for all resources or 'summary' for key services",
	Required:    true,
	Type:        types.String,
	Value:       "full",
	ValueList:   []string{"full", "summary"},
}

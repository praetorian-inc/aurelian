package types

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	TypeName   string      `json:"TypeName"`
	Region     string      `json:"Region"`
	Properties interface{} `json:"Properties"`
	AccountId  string      `json:"AccountId"`
	Arn        arn.ARN     `json:"Arn"`
}

func (e *EnrichedResourceDescription) ToArn() arn.ARN {
	a := arn.ARN{
		Partition: "aws",
		Service:   e.Service(),
		Region:    e.Region,
		AccountID: e.AccountId,
		Resource:  e.Identifier,
	}
	return a
}

func NewEnrichedResourceDescription(identifier, typeName, region, accountId string, properties interface{}) EnrichedResourceDescription {
	a := BuildResourceARN(identifier, typeName, region, accountId)

	// SQS special case: extract queue name from the parsed ARN
	if typeName == "AWS::SQS::Queue" && a.Resource != "" {
		identifier = a.Resource
	}

	return EnrichedResourceDescription{
		Identifier: identifier,
		TypeName:   typeName,
		Region:     region,
		Properties: properties,
		AccountId:  accountId,
		Arn:        a,
	}
}

// BuildResourceARN constructs an ARN from a resource's identifier, type, region,
// and account. It encodes AWS-specific conventions (e.g., S3 buckets are regionless,
// SQS identifiers are URLs, service entries get wildcard ARNs).
func BuildResourceARN(identifier, typeName, region, accountId string) arn.ARN {
	switch typeName {
	case "AWS::SQS::Queue":
		// first, check if SQS URL
		parsed, err := SQSUrlToArn(identifier)
		if err == nil {
			return parsed
		}

		return arn.ARN{
			Partition: "aws",
			Service:   "sqs",
			Region:    region,
			AccountID: accountId,
			Resource:  identifier,
		}
	case "AWS::EC2::Instance":
		return arn.ARN{
			Partition: "aws",
			Service:   "ec2",
			Region:    region,
			AccountID: accountId,
			Resource:  "instance/" + identifier,
		}
	case "AWS::S3::Bucket":
		return arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "",
			AccountID: "",
			Resource:  identifier,
		}
	case "AWS::Lambda::Function":
		parsed, err := arn.Parse(identifier)
		if err == nil {
			return parsed
		}
		return arn.ARN{
			Partition: "aws",
			Service:   "lambda",
			Region:    region,
			AccountID: accountId,
			Resource:  "function:" + identifier,
		}
	case "AWS::Service":
		return arn.ARN{
			Partition: "aws",
			Service:   strings.Split(identifier, ".")[0],
			Region:    "*",
			AccountID: "*",
			Resource:  "*",
		}
	default:
		parsed, err := arn.Parse(identifier)
		if err == nil {
			return parsed
		}
		return arn.ARN{
			Partition: "aws",
			Service:   extractServiceFromTypeName(typeName),
			Region:    region,
			AccountID: accountId,
			Resource:  identifier,
		}
	}
}

func NewEnrichedResourceDescriptionFromArn(a string) (EnrichedResourceDescription, error) {
	parsed, err := arn.Parse(a)
	if err != nil {
		return EnrichedResourceDescription{}, err
	}

	typename, ok := ResolveResourceType(parsed.Service, parsed.Resource)
	if !ok {
		typename = fmt.Sprintf("AWS::%s::Unknown", parsed.Service)
	}

	return EnrichedResourceDescription{
		Identifier: parsed.Resource,
		TypeName:   typename,
		Region:     parsed.Region,
		AccountId:  parsed.AccountID,
		Arn:        parsed,
	}, nil
}

type resourceProperties struct {
	Tags []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Tags"`
}

func (e *EnrichedResourceDescription) Tags() map[string]string {
	if e.Properties == nil {
		return map[string]string{}
	}

	propsStr, ok := e.Properties.(string)
	if !ok {
		return map[string]string{}
	}

	var props resourceProperties
	if err := json.Unmarshal([]byte(propsStr), &props); err != nil {
		return map[string]string{}
	}

	tags := make(map[string]string, len(props.Tags))
	for _, tag := range props.Tags {
		tags[tag.Key] = tag.Value
	}

	return tags
}

func (e *EnrichedResourceDescription) Service() string {
	if e.TypeName == "AWS::Service" {
		split := strings.Split(e.Identifier, ".")
		return split[0]
	}

	return extractServiceFromTypeName(e.TypeName)
}

func extractServiceFromTypeName(typeName string) string {
	split := strings.Split(typeName, "::")
	if len(split) < 3 {
		slog.Debug("Failed to parse resource type", slog.String("resourceType", typeName))
		return ""
	}

	service := strings.ToLower(split[1])
	return service
}

func (e *EnrichedResourceDescription) Type() string {
	split := strings.Split(e.TypeName, "::")
	if len(split) < 3 {
		slog.Debug("Failed to parse resource type", slog.String("resourceType", e.TypeName))
		return ""
	}

	return split[2]
}

func SQSUrlToArn(sqsUrl string) (arn.ARN, error) {
	// Format: https://sqs.{region}.amazonaws.com/{accountId}/{queueName}
	parts := strings.Split(sqsUrl, ".")
	if len(parts) < 4 || !strings.HasPrefix(sqsUrl, "https://sqs.") {
		return arn.ARN{}, fmt.Errorf("invalid SQS URL format: %s", sqsUrl)
	}

	region := parts[1]

	pathParts := strings.Split(parts[3], "/")
	if len(pathParts) < 3 {
		return arn.ARN{}, fmt.Errorf("invalid SQS URL path format: %s", sqsUrl)
	}

	accountId := pathParts[1]
	queueName := pathParts[2]

	a := arn.ARN{
		Partition: "aws",
		Service:   "sqs",
		Region:    region,
		AccountID: accountId,
		Resource:  queueName,
	}

	return a, nil
}

func (erd *EnrichedResourceDescription) PropertiesAsMap() (map[string]any, error) {
	rawProps, ok := erd.Properties.(string)
	if !ok {
		return nil, fmt.Errorf("properties are not a string")
	}

	var props map[string]any
	err := json.Unmarshal([]byte(rawProps), &props)
	if err != nil {
		return nil, err
	}

	return props, nil
}

func (e *EnrichedResourceDescription) GetRoleArn() string {
	if e.Properties == nil {
		return ""
	}

	_, ok := e.Properties.(string)
	if !ok {
		return ""
	}

	props, err := e.PropertiesAsMap()
	if err != nil {
		return ""
	}

	switch e.TypeName {
	case "AWS::Lambda::Function":
		if roleArn, ok := props["Role"].(string); ok {
			return roleArn
		}
	case "AWS::EC2::Instance":
		if profile, ok := props["IamInstanceProfile"].(string); ok {
			return profile
		}
		if profileObj, ok := props["IamInstanceProfile"].(map[string]any); ok {
			if arn, ok := profileObj["Arn"].(string); ok {
				return arn
			}
		}
	case "AWS::CloudFormation::Stack":
		if roleArn, ok := props["RoleARN"].(string); ok {
			return roleArn
		}
	}

	return ""
}

// ResolveResourceType determines the CloudControl resource type from an ARN's
// service and resource components. The resource identifier is used to
// disambiguate services that expose multiple resource types (e.g. ECS clusters
// vs task definitions, IAM roles vs users vs policies).
func ResolveResourceType(service, resource string) (string, bool) {
	// Check service+resource prefix rules first for ambiguous services.
	if prefixes, ok := serviceResourcePrefixes[service]; ok {
		for _, entry := range prefixes {
			if strings.HasPrefix(resource, entry.prefix) {
				return entry.resourceType, true
			}
		}
	}

	// Fall back to default service mapping.
	rt, ok := serviceDefaultResourceType[service]
	return rt, ok
}

type resourcePrefixEntry struct {
	prefix       string
	resourceType string
}

// serviceResourcePrefixes maps services with multiple resource types to
// prefix-based disambiguation rules. Entries are checked in order; the first
// matching prefix wins.
var serviceResourcePrefixes = map[string][]resourcePrefixEntry{
	"ecs": {
		{prefix: "task-definition/", resourceType: "AWS::ECS::TaskDefinition"},
		{prefix: "service/", resourceType: "AWS::ECS::Service"},
		{prefix: "cluster/", resourceType: "AWS::ECS::Cluster"},
	},
	"iam": {
		{prefix: "role/", resourceType: "AWS::IAM::Role"},
		{prefix: "user/", resourceType: "AWS::IAM::User"},
		{prefix: "policy/", resourceType: "AWS::IAM::Policy"},
		{prefix: "group/", resourceType: "AWS::IAM::Group"},
		{prefix: "instance-profile/", resourceType: "AWS::IAM::InstanceProfile"},
	},
	"ec2": {
		{prefix: "instance/", resourceType: "AWS::EC2::Instance"},
		{prefix: "security-group/", resourceType: "AWS::EC2::SecurityGroup"},
		{prefix: "subnet/", resourceType: "AWS::EC2::Subnet"},
		{prefix: "vpc/", resourceType: "AWS::EC2::VPC"},
	},
	"ssm": {
		{prefix: "document/", resourceType: "AWS::SSM::Document"},
		{prefix: "parameter/", resourceType: "AWS::SSM::Parameter"},
	},
	"rds": {
		{prefix: "cluster:", resourceType: "AWS::RDS::DBCluster"},
		{prefix: "db:", resourceType: "AWS::RDS::DBInstance"},
	},
}

// serviceDefaultResourceType is the fallback when no prefix rule matches.
var serviceDefaultResourceType = map[string]string{
	"amplify":           "AWS::Amplify::App",
	"ec2":               "AWS::EC2::Instance",
	"s3":                "AWS::S3::Bucket",
	"lambda":            "AWS::Lambda::Function",
	"iam":               "AWS::IAM::Role",
	"cloudformation":    "AWS::CloudFormation::Stack",
	"sqs":               "AWS::SQS::Queue",
	"sns":               "AWS::SNS::Topic",
	"rds":               "AWS::RDS::DBInstance",
	"dynamodb":          "AWS::DynamoDB::Table",
	"ecr":               "AWS::ECR::Repository",
	"ecs":               "AWS::ECS::Cluster",
	"elasticache":       "AWS::ElastiCache::CacheCluster",
	"elasticsearch":     "AWS::Elasticsearch::Domain",
	"apigateway":        "AWS::ApiGateway::RestApi",
	"kms":               "AWS::KMS::Key",
	"secretsmanager":    "AWS::SecretsManager::Secret",
	"ssm":               "AWS::SSM::Parameter",
	"elasticfilesystem": "AWS::EFS::FileSystem",
	"cognito-idp":       "AWS::Cognito::UserPool",
	"states":            "AWS::StepFunctions::StateMachine",
	"logs":              "AWS::Logs::LogGroup",
}

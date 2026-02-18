package types

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
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
	a := arn.ARN{}
	switch typeName {
	case "AWS::SQS::Queue":
		arn, err := SQSUrlToArn(identifier)
		if err == nil {
			a = arn
			// Extract queue name from the ARN resource to use as identifier
			identifier = arn.Resource
		}
	case "AWS::EC2::Instance":
		a = arn.ARN{
			Partition: "aws",
			Service:   "ec2",
			Region:    region,
			AccountID: accountId,
			Resource:  "instance/" + identifier,
		}
	case "AWS::S3::Bucket":
		a = arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Region:    "",
			AccountID: "",
			Resource:  identifier,
		}
	case "AWS::Lambda::Function":
		parsed, err := arn.Parse(identifier)
		if err == nil {
			a = parsed
		} else {
			a = arn.ARN{
				Partition: "aws",
				Service:   "lambda",
				Region:    region,
				AccountID: accountId,
				Resource:  "function:" + identifier,
			}
		}
	case "AWS::Service":
		a = arn.ARN{
			Partition: "aws",
			Service:   strings.Split(identifier, ".")[0],
			Region:    "*",
			AccountID: "*",
			Resource:  "*",
		}
	default:
		parsed, err := arn.Parse(identifier)
		if err == nil {
			a = parsed
		} else {
			serviceName := extractServiceFromTypeName(typeName)
			a = arn.ARN{
				Partition: "aws",
				Service:   serviceName,
				Region:    region,
				AccountID: accountId,
				Resource:  identifier,
			}
		}

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

func NewEnrichedResourceDescriptionFromArn(a string) (EnrichedResourceDescription, error) {
	parsed, err := arn.Parse(a)
	if err != nil {
		return EnrichedResourceDescription{}, err
	}

	typename := ServiceToResourceType[parsed.Service]
	if _, ok := ServiceToResourceType[parsed.Service]; !ok {
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

// func (erd *EnrichedResourceDescription) ToNPInputs() ([]NpInput, error) {
// 	propsJson, err := json.Marshal(erd.Properties)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return []NpInput{
// 		{
// 			ContentBase64: base64.StdEncoding.EncodeToString(propsJson),
// 			Provenance: NpProvenance{
// 				Platform:     "aws",
// 				ResourceType: erd.TypeName,
// 				ResourceID:   erd.Arn.String(),
// 				Region:       erd.Region,
// 				AccountID:    erd.AccountId,
// 			},
// 		},
// 	}, nil

// }

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

// ToAWSResource converts the EnrichedResourceDescription to an output.AWSResource
func (erd *EnrichedResourceDescription) ToAWSResource() output.AWSResource {
	resource := output.AWSResource{
		Platform:     "aws",
		ResourceType: erd.TypeName,
		ResourceID:   erd.Identifier,
		ARN:          erd.Arn.String(),
		AccountRef:   erd.AccountId,
		Region:       erd.Region,
	}

	// Use PropertiesAsMap for proper conversion
	if propsMap, err := erd.PropertiesAsMap(); err == nil {
		resource.Properties = propsMap
	} else if m, ok := erd.Properties.(map[string]any); ok {
		resource.Properties = m
	} else {
		resource.Properties = map[string]any{"raw_properties": erd.Properties}
	}

	return resource
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

var ServiceToResourceType = map[string]string{
	"ec2":            "AWS::EC2::Instance",
	"s3":             "AWS::S3::Bucket",
	"lambda":         "AWS::Lambda::Function",
	"iam":            "AWS::IAM::Role",
	"cloudformation": "AWS::CloudFormation::Stack",
	"sqs":            "AWS::SQS::Queue",
	"sns":            "AWS::SNS::Topic",
	"rds":            "AWS::RDS::DBInstance",
	"dynamodb":       "AWS::DynamoDB::Table",
	"ecr":            "AWS::ECR::Repository",
	"ecs":            "AWS::ECS::Cluster",
	"elasticache":    "AWS::ElastiCache::CacheCluster",
	"elasticsearch":  "AWS::Elasticsearch::Domain",
	"apigateway":     "AWS::ApiGateway::RestApi",
	"kms":            "AWS::KMS::Key",
	"secretsmanager": "AWS::SecretsManager::Secret",
	"ssm":            "AWS::SSM::Parameter",
}


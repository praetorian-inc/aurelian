package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
)

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	TypeName   string      `json:"TypeName"`
	Region     string      `json:"Region"` //additional field to enrich
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
			a = arn.ARN{
				Partition: "aws",
				Service:   typeName,
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

	return EnrichedResourceDescription{
		Identifier: parsed.String(),
		TypeName:   parsed.Resource,
		Region:     parsed.Region,
		AccountId:  parsed.AccountID,
		Arn:        parsed,
	}, nil
}

func NewEnrichedResourceDescriptionFromRoleDL(roleDL RoleDL) *EnrichedResourceDescription {
	arn, _ := arn.Parse(roleDL.Arn)

	return &EnrichedResourceDescription{
		Identifier: roleDL.RoleName,
		TypeName:   "AWS::IAM::Role",
		Region:     "",
		AccountId:  arn.AccountID,
		Arn:        arn,
	}
}

func NewEnrichedResourceDescriptionFromPolicyDL(policyDL PoliciesDL) *EnrichedResourceDescription {
	arn, _ := arn.Parse(policyDL.Arn)

	return &EnrichedResourceDescription{
		Identifier: policyDL.PolicyName,
		TypeName:   "AWS::IAM::ManagedPolicy",
		Region:     "",
		AccountId:  arn.AccountID,
		Arn:        arn,
	}
}

func NewEnrichedResourceDescriptionFromUserDL(userDL UserDL) *EnrichedResourceDescription {
	arn, _ := arn.Parse(userDL.Arn)

	return &EnrichedResourceDescription{
		Identifier: userDL.UserName,
		TypeName:   "AWS::IAM::User",
		Region:     "",
		AccountId:  arn.AccountID,
		Arn:        arn,
	}
}

func NewEnrichedResourceDescriptionFromGroupDL(groupDL GroupDL) *EnrichedResourceDescription {
	arn, _ := arn.Parse(groupDL.Arn)

	return &EnrichedResourceDescription{
		Identifier: groupDL.GroupName,
		TypeName:   "AWS::IAM::Group",
		Region:     "",
		AccountId:  arn.AccountID,
		Arn:        arn,
	}
}

// Helper struct to unmarshal the Properties JSON string
type resourceProperties struct {
	Tags []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Tags"`
}

// Tags returns the list of tag keys from the Properties field
func (e *EnrichedResourceDescription) Tags() map[string]string {
	// Handle case where Properties is empty or nil
	if e.Properties == nil {
		return map[string]string{}
	}

	// Convert Properties to string if it's not already
	propsStr, ok := e.Properties.(string)
	if !ok {
		return map[string]string{}
	}

	// Unmarshal the Properties JSON string
	var props resourceProperties
	if err := json.Unmarshal([]byte(propsStr), &props); err != nil {
		return map[string]string{}
	}

	// Extract just the tag keys
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

	split := strings.Split(e.TypeName, "::")
	if len(split) < 3 {
		slog.Debug("Failed to parse resource type", slog.String("resourceType", e.TypeName))
		return ""
	}

	service := strings.ToLower(split[1])
	return service
}

func (erd *EnrichedResourceDescription) ToNPInputs() ([]jtypes.NPInput, error) {
	propsJson, err := json.Marshal(erd.Properties)
	if err != nil {
		return nil, err
	}

	return []jtypes.NPInput{
		{
			ContentBase64: base64.StdEncoding.EncodeToString(propsJson),
			Provenance: jtypes.NPProvenance{
				Platform:     "aws",
				ResourceType: erd.TypeName,
				ResourceID:   erd.Arn.String(),
				Region:       erd.Region,
				AccountID:    erd.AccountId,
			},
		},
	}, nil

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
	// Parse URL to extract components
	// Format: https://sqs.{region}.amazonaws.com/{accountId}/{queueName}
	parts := strings.Split(sqsUrl, ".")
	if len(parts) < 4 || !strings.HasPrefix(sqsUrl, "https://sqs.") {
		return arn.ARN{}, fmt.Errorf("invalid SQS URL format: %s", sqsUrl)
	}

	region := parts[1]

	// Extract account ID and queue name from the path
	pathParts := strings.Split(parts[3], "/")
	if len(pathParts) < 3 {
		return arn.ARN{}, fmt.Errorf("invalid SQS URL path format: %s", sqsUrl)
	}

	accountId := pathParts[1]
	queueName := pathParts[2]

	// Construct the ARN
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

// GetRoleArn extracts the IAM role ARN from resource properties if it exists
func (e *EnrichedResourceDescription) GetRoleArn() string {
	// Handle case where Properties is empty or nil
	if e.Properties == nil {
		return ""
	}

	// Convert Properties to check if it's a string
	_, ok := e.Properties.(string)
	if !ok {
		return ""
	}

	// Use PropertiesAsMap to get a map of properties
	props, err := e.PropertiesAsMap()
	if err != nil {
		return ""
	}

	// Check resource type and extract role ARN accordingly
	switch e.TypeName {
	case "AWS::Lambda::Function":
		if roleArn, ok := props["Role"].(string); ok {
			return roleArn
		}
	case "AWS::EC2::Instance":
		if profile, ok := props["IamInstanceProfile"].(string); ok {
			return profile
		}
		// Some EC2 instances have a nested IamInstanceProfile object
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

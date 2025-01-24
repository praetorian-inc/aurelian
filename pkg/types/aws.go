package types

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	TypeName   string      `json:"TypeName"`
	Region     string      `json:"Region"` //additional field to enrich
	Properties interface{} `json:"Properties"`
	AccountId  string
	Arn        arn.ARN
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

func ArnFromEnrichedResourceDescription(e EnrichedResourceDescription) arn.ARN {
	a := arn.ARN{
		Partition: "aws",
		Service:   getServiceName(e.TypeName),
		Region:    e.Region,
		AccountID: e.AccountId,
		Resource:  e.Identifier,
	}
	return a
}

func getServiceName(resourceType string) string {
	service := strings.ToLower(strings.Split(resourceType, "::")[1])
	return service
}

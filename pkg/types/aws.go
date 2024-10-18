package types

import "github.com/aws/aws-sdk-go-v2/aws/arn"

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	TypeName   string      `json:"TypeName"`
	Region     string      `json:"Region"` //additional field to enrich
	Properties interface{} `json:"Properties"`
	AccountId  string
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
	}, nil
}

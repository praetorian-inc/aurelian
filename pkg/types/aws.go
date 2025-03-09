package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
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

func (e *EnrichedResourceDescription) ToArn() arn.ARN {
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

func (erd *EnrichedResourceDescription) ToNPInput() (jtypes.NPInput, error) {
	propsJson, err := json.Marshal(erd.Properties)
	if err != nil {
		return jtypes.NPInput{}, err
	}

	return jtypes.NPInput{
		ContentBase64: base64.StdEncoding.EncodeToString(propsJson),
		Provenance: jtypes.NPProvenance{
			Platform:     "aws",
			ResourceType: erd.TypeName,
			ResourceID:   erd.Arn.String(),
			Region:       erd.Region,
			AccountID:    erd.AccountId,
		},
	}, nil
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

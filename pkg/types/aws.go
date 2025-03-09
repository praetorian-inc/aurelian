package types

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/janus/pkg/types"
)

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	TypeName   string      `json:"TypeName"`
	Region     string      `json:"Region"` //additional field to enrich
	Properties interface{} `json:"Properties"`
	AccountId  string      `json:"AccountId"`
	Arn        arn.ARN     `json:"Arn"`
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
		Service:   e.Service(),
		Region:    e.Region,
		AccountID: e.AccountId,
		Resource:  e.Identifier,
	}
	return a
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
	split := strings.Split(e.TypeName, "::")
	if len(split) < 3 {
		slog.Debug("Failed to parse resource type", slog.String("resourceType", e.TypeName))
		return ""
	}

	service := strings.ToLower(split[1])
	return service
}

func (erd *EnrichedResourceDescription) ToNPInput() (types.NPInput, error) {
	propsJson, err := json.Marshal(erd.Properties)
	if err != nil {
		return types.NPInput{}, err
	}

	return types.NPInput{
		ContentBase64: base64.StdEncoding.EncodeToString(propsJson),
		Provenance: types.NPProvenance{
			Platform:     "aws",
			ResourceType: erd.TypeName,
			ResourceID:   erd.Arn.String(),
			Region:       erd.Region,
			AccountID:    erd.AccountId,
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

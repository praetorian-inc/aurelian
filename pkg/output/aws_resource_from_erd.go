package output

import "github.com/praetorian-inc/aurelian/pkg/types"

// AWSResourceFromERD converts an EnrichedResourceDescription to an AWSResource.
func AWSResourceFromERD(erd *types.EnrichedResourceDescription) AWSResource {
	resource := AWSResource{
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

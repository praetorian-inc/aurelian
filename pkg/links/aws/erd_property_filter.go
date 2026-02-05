package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// PropertyFilterLink is a custom link that filters EnrichedResourceDescription objects
// based on whether they have a specific property.
type PropertyFilterLink struct {
	*base.NativeAWSLink
}

// NewPropertyFilterLink creates a link that filters EnrichedResourceDescription objects
// based on whether they have a specific property.
func NewPropertyFilterLink(args map[string]any) *PropertyFilterLink {
	return &PropertyFilterLink{
		NativeAWSLink: base.NewNativeAWSLink("property-filter", args),
	}
}

// Parameters defines the parameters accepted by the PropertyFilterLink
func (pfl *PropertyFilterLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("property", "The property name to check for", plugin.WithRequired()),
	}
}

// Process handles the filtering logic
func (pfl *PropertyFilterLink) Process(ctx context.Context, input any) ([]any, error) {
	erd, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, nil
	}

	// Get the property to check for from the link configuration
	propertyName := pfl.ArgString("property", "")
	if propertyName == "" {
		return nil, fmt.Errorf("property name not specified in configuration")
	}

	// Handle case where Properties is empty or nil
	if erd.Properties == nil {
		return pfl.Outputs(), nil // Skip this resource
	}

	// Convert Properties to string if it's not already
	propsStr, ok := erd.Properties.(string)
	if !ok {
		// Try to marshal it to see if we can use it
		propsBytes, err := json.Marshal(erd.Properties)
		if err != nil {
			slog.Error("Failed to marshal properties", "error", err, "properties", erd.Properties)
			return pfl.Outputs(), nil // Skip this resource
		}
		propsStr = string(propsBytes)
	}

	// The properties string is often double-escaped, so we need to unescape it
	if propsStr[0] == '"' {
		var unescaped string
		if err := json.Unmarshal([]byte(propsStr), &unescaped); err != nil {
			slog.Error("Failed to unescape properties", "error", err)
			return pfl.Outputs(), nil
		}
		propsStr = unescaped
	}

	// Unmarshal the unescaped properties string
	var propsMap map[string]interface{}
	if err := json.Unmarshal([]byte(propsStr), &propsMap); err != nil {
		slog.Error("Failed to unmarshal properties", "error", err, "propertiesStr", propsStr)
		return pfl.Outputs(), nil // Skip this resource
	}

	// Check if the property exists and is not nil/empty
	value, exists := propsMap[propertyName]
	if !exists {
		return pfl.Outputs(), nil // Skip this resource
	}

	// Check if the value is empty
	if isEmpty(value) {
		return pfl.Outputs(), nil // Skip this resource
	}

	// Property exists and is not empty, add NeedsManualTriage for EC2 instances
	if erd.TypeName == "AWS::EC2::Instance" {
		// EC2 instances with public IPs need manual triage for network path evaluation
		propsMap["NeedsManualTriage"] = true

		// Update the properties in the ERD with the modified map
		updatedPropsBytes, err := json.Marshal(propsMap)
		if err != nil {
			slog.Error("Failed to marshal updated properties", "error", err)
			pfl.Send(erd)
			return pfl.Outputs(), nil
		}

		// Create a new ERD with updated properties
		updatedERD := *erd // Copy the ERD
		updatedERD.Properties = string(updatedPropsBytes)
		pfl.Send(&updatedERD)
	} else {
		// For other resource types, send the original ERD
		pfl.Send(erd)
	}
	return pfl.Outputs(), nil
}

// isEmpty checks if a value is considered empty
func isEmpty(value interface{}) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	}

	return false
}

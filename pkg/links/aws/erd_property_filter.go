package aws

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// PropertyFilterLink is a custom link that filters EnrichedResourceDescription objects
// based on whether they have a specific property.
type PropertyFilterLink struct {
	*chain.Base
}

// NewPropertyFilterLink creates a link that filters EnrichedResourceDescription objects
// based on whether they have a specific property.
func NewPropertyFilterLink(configs ...cfg.Config) chain.Link {
	pfl := &PropertyFilterLink{}
	pfl.Base = chain.NewBase(pfl, configs...)
	return pfl
}

// Params defines the parameters accepted by the PropertyFilterLink
func (pfl *PropertyFilterLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("property", "The property name to check for").AsRequired(),
	}
}

// Process handles the filtering logic
func (pfl *PropertyFilterLink) Process(erd *types.EnrichedResourceDescription) error {
	// Get the property to check for from the link configuration
	propertyName, err := cfg.As[string](pfl.Arg("property"))
	if err != nil {
		return fmt.Errorf("property name not specified in configuration: %w", err)
	}

	// Handle case where Properties is empty or nil
	if erd.Properties == nil {
		return nil // Skip this resource
	}

	// Convert Properties to string if it's not already
	propsStr, ok := erd.Properties.(string)
	if !ok {
		// Try to marshal it to see if we can use it
		propsBytes, err := json.Marshal(erd.Properties)
		if err != nil {
			slog.Error("Failed to marshal properties", "error", err, "properties", erd.Properties)
			return nil // Skip this resource
		}
		propsStr = string(propsBytes)
	}

	// The properties string is often double-escaped, so we need to unescape it
	if propsStr[0] == '"' {
		var unescaped string
		if err := json.Unmarshal([]byte(propsStr), &unescaped); err != nil {
			slog.Error("Failed to unescape properties", "error", err)
			return nil
		}
		propsStr = unescaped
	}

	// Unmarshal the unescaped properties string
	var propsMap map[string]interface{}
	if err := json.Unmarshal([]byte(propsStr), &propsMap); err != nil {
		slog.Error("Failed to unmarshal properties", "error", err, "propertiesStr", propsStr)
		return nil // Skip this resource
	}

	// Check if the property exists and is not nil/empty
	value, exists := propsMap[propertyName]
	if !exists {
		return nil // Skip this resource
	}

	// Check if the value is empty
	if isEmpty(value) {
		return nil // Skip this resource
	}

	// Property exists and is not empty, send the original ERD
	pfl.Send(erd)
	return nil
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

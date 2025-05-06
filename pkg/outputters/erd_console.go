package outputters

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// PropertyExtractor defines a function that can extract specific information from a resource's properties
type PropertyExtractor func(properties map[string]any) (string, []string, bool)

type ERDConsoleOutputter struct {
	*chain.BaseOutputter
	// Map of resource type to property extractor function
	extractors map[string]PropertyExtractor
}

// NewERDConsoleOutputter creates a new console outputter for ERD types
func NewERDConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)

	// Register default extractors
	o.registerDefaultExtractors()

	return o
}

// RegisterExtractor allows adding custom extractors for specific resource types
func (o *ERDConsoleOutputter) RegisterExtractor(resourceType string, extractor PropertyExtractor) {
	o.extractors[resourceType] = extractor
}

// registerDefaultExtractors sets up the default property extractors
func (o *ERDConsoleOutputter) registerDefaultExtractors() {
	// Default extractor for resources with Actions
	o.RegisterExtractor("default-actions", func(props map[string]any) (string, []string, bool) {
		if actions, ok := props["Actions"].([]any); ok {
			strActions := make([]string, len(actions))
			for i, action := range actions {
				if strAction, ok := action.(string); ok {
					strActions[i] = strAction
				}
			}
			return "", strActions, len(strActions) > 0
		}
		return "", nil, false
	})

	// EC2 Instance extractor
	o.RegisterExtractor("AWS::EC2::Instance", func(props map[string]any) (string, []string, bool) {
		if publicIp, ok := props["PublicIp"].(string); ok && publicIp != "" {
			return publicIp, nil, true
		}
		return "", nil, false
	})

	// RDS Instance extractor
	o.RegisterExtractor("AWS::RDS::DBInstance", func(props map[string]any) (string, []string, bool) {
		if endpoint, ok := props["Endpoint"].(map[string]any); ok {
			address, addressOk := endpoint["Address"].(string)
			port, portOk := endpoint["Port"].(string)

			if addressOk && portOk && address != "" {
				return fmt.Sprintf("%s:%s", address, port), nil, true
			}
		}
		return "", nil, false
	})

	// Add more resource type extractors as needed...
}

// getPropertiesMap ensures we have a proper map[string]any from various potential property formats
func (o *ERDConsoleOutputter) getPropertiesMap(properties any) (map[string]any, error) {
	// If it's already a map, use it
	if propsMap, ok := properties.(map[string]any); ok {
		return propsMap, nil
	}

	// If it's a string, try to unmarshal it
	if propsStr, ok := properties.(string); ok {
		var propsMap map[string]any
		if err := json.Unmarshal([]byte(propsStr), &propsMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal properties string: %w", err)
		}
		return propsMap, nil
	}

	// Otherwise, try to convert through JSON marshaling/unmarshaling
	propsData, err := json.Marshal(properties)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}

	var propsMap map[string]any
	if err := json.Unmarshal(propsData, &propsMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal properties data: %w", err)
	}

	return propsMap, nil
}

// extractActions attempts to extract action strings from properties
func (o *ERDConsoleOutputter) extractActions(props map[string]any) []string {
	// Check for Actions directly
	if actionsAny, ok := props["Actions"]; ok {
		// Handle case where Actions is already a []string
		if actions, ok := actionsAny.([]string); ok {
			return actions
		}

		// Handle case where Actions is a []any
		if actionsArray, ok := actionsAny.([]any); ok {
			actions := make([]string, 0, len(actionsArray))
			for _, a := range actionsArray {
				if strAction, ok := a.(string); ok {
					actions = append(actions, strAction)
				}
			}
			return actions
		}
	}

	// Check for AccessPolicy which is common in public resources
	if policy, ok := props["AccessPolicy"]; ok && policy != nil {
		if policyStr, ok := policy.(string); ok && policyStr != "" {
			return []string{"Has custom access policy: " + policyStr}
		}
	}

	return nil
}

// Output prints an item to the console, assuming it's a pointer to EnrichedResourceDescription
func (o *ERDConsoleOutputter) Output(v any) error {
	erd, ok := v.(*types.EnrichedResourceDescription)
	if !ok {
		return nil // Not an ERD pointer, silently ignore
	}

	// Get properties as a map
	propsMap, err := o.getPropertiesMap(erd.Properties)
	if err != nil {
		slog.Warn("Could not process properties for resource",
			"error", err,
			"resourceType", erd.TypeName,
			"resourceId", erd.Identifier)
		// Still output the ARN even if we can't extract properties
		message.Success("%s", erd.Arn.String())
		return nil
	}

	// Try type-specific extractor first
	if extractor, ok := o.extractors[erd.TypeName]; ok {
		if publicIp, actions, success := extractor(propsMap); success {
			o.outputResource(erd.Arn.String(), publicIp, actions)
			return nil
		}
	}

	// Extract actions - this ensures we don't lose Actions output for other types
	actions := o.extractActions(propsMap)
	if len(actions) > 0 {
		o.outputResource(erd.Arn.String(), "", actions)
		return nil
	}

	// No special formatting, just output the ARN
	message.Success("%s", erd.Arn.String())
	return nil
}

// outputResource handles the formatting of the resource output
func (o *ERDConsoleOutputter) outputResource(arn string, publicIp string, actions []string) {
	if len(actions) > 0 {
		actionsOut := strings.Join(actions, "\n    ")
		message.Success("%s\n    %s", arn, actionsOut)
	} else if publicIp != "" {
		message.Success("%s\n    Public IP: %s", arn, publicIp)
	} else {
		message.Success("%s", arn)
	}
}

// Initialize is called when the outputter is initialized
func (o *ERDConsoleOutputter) Initialize() error {
	return nil
}

// Complete is called when the chain is complete
func (o *ERDConsoleOutputter) Complete() error {
	return nil
}

// Params returns the parameters for this outputter
func (o *ERDConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{
		// No additional parameters needed
	}
}

type RDSEndpoint struct {
	Address      string `json:"Address"`
	Port         string `json:"Port"`
	HostedZoneID string `json:"HostedZoneID"`
}

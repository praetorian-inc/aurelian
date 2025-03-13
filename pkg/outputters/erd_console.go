package outputters

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type ERDConsoleOutputter struct {
	*chain.BaseOutputter
}

// NewERDConsoleOutputter creates a new console outputter for ERD types
func NewERDConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &ERDConsoleOutputter{}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output prints an item to the console, assuming it's a pointer to EnrichedResourceDescription
func (o *ERDConsoleOutputter) Output(v any) error {
	erd, ok := v.(*types.EnrichedResourceDescription)
	if !ok {
		return nil // Not an ERD pointer, silently ignore
	}

	// Extract the Actions from Properties if it exists
	var publicIp string
	var actions []string
	propertiesMap, ok := erd.Properties.(map[string]any)
	if ok {
		if a, ok := propertiesMap["Actions"].([]string); ok {
			actions = a
		} else if ip, ok := propertiesMap["PublicIp"].(string); ok {
			publicIp = ip
		}
	} else {
		if err := json.Unmarshal([]byte(erd.Properties.(string)), &propertiesMap); err != nil {
			slog.Error("Failed to unmarshal properties", "error", err, "properties", erd.Properties)
			return nil // Skip this resource
		}
		publicIp = propertiesMap["PublicIp"].(string)
	}

	if actions != nil {
		actionsOut := strings.Join(actions, "\n    ")
		message.Success("%s\n    %s", erd.Arn.String(), actionsOut)
	} else if publicIp != "" {
		message.Success("%s\n    Public IP: %s", erd.Arn.String(), publicIp)
	} else {
		message.Success("%s", erd.Arn.String())
	}

	return nil
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

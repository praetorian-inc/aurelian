package general

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

// JqFilter is a link that filters JSON data using jq.
type JqFilter struct {
	*plugin.BaseLink
	filter string
}

// NewJqFilter creates a new JqFilter link.
func NewJqFilter(args map[string]any) *JqFilter {
	jq := &JqFilter{
		BaseLink: plugin.NewBaseLink("jq-filter", args),
	}

	// Initialize filter from args
	jq.filter = jq.ArgString("filter", "")

	return jq
}

// Parameters defines the parameters for the JqFilter link.
func (jq *JqFilter) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "filter",
			Description: "jq filter expression",
			Required:    true,
			Type:        "string",
		},
	}
}

// Validate checks if jq is installed and available.
func (jq *JqFilter) Validate() error {
	_, err := exec.LookPath("jq")
	if err != nil {
		return fmt.Errorf("jq command not found: %w", err)
	}
	if jq.filter == "" {
		return fmt.Errorf("filter parameter is required")
	}
	return nil
}

// Process applies the jq filter to the input JSON data.
func (jq *JqFilter) Process(ctx context.Context, input any) ([]any, error) {
	// Validate first
	if err := jq.Validate(); err != nil {
		return nil, err
	}

	// Convert input to JSON bytes
	jsonData, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input to JSON: %w", err)
	}

	results, err := utils.PerformJqQuery(jsonData, jq.filter)
	if err != nil {
		return nil, fmt.Errorf("failed to filter JSON data: %w", err)
	}

	// Check if output is empty
	if len(results) == 0 {
		return []any{}, nil
	}

	var output any
	err = json.Unmarshal(results, &output)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal filtered JSON data: %w", err)
	}

	return []any{output}, nil
}

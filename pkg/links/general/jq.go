package general

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// JqFilter is a link that filters JSON data using jq.
type JqFilter struct {
	*chain.Base
	filter string
}

// NewJqFilter creates a new JqFilter link.
func NewJqFilter(configs ...cfg.Config) chain.Link {
	jq := &JqFilter{}
	jq.Base = chain.NewBase(jq, configs...)
	return jq
}

// Params defines the parameters for the JqFilter link.
func (jq *JqFilter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("filter", "jq filter expression").AsRequired(),
	}
}

// Validate checks if jq is installed and available.
func (jq *JqFilter) Validate() error {
	_, err := exec.LookPath("jq")
	if err != nil {
		return fmt.Errorf("jq command not found: %w", err)
	}
	return nil
}

// Initialize sets up the JqFilter with the provided filter expression.
func (jq *JqFilter) Initialize() error {
	var err error
	jq.filter, err = cfg.As[string](jq.Arg("filter"))
	if err != nil {
		return fmt.Errorf("failed to get filter: %w", err)
	}
	return nil
}

// Process applies the jq filter to the input JSON data.
func (jq *JqFilter) Process(input any) error {
	// Convert input to JSON bytes
	jsonData, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input to JSON: %w", err)
	}

	results, err := utils.PerformJqQuery(jsonData, jq.filter)
	if err != nil {
		return fmt.Errorf("failed to filter JSON data: %w", err)
	}

	// Check if output is empty
	if len(results) == 0 {
		return nil
	}

	var output any
	err = json.Unmarshal(results, &output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal filtered JSON data: %w", err)
	}

	jq.Send(output)
	return nil
}

package outputters

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type RiskConsoleOutputter struct {
	*chain.BaseOutputter
	riskGroups map[string][]model.Risk // Map to store risks grouped by name
}

// RiskInstance represents a single instance of a risk
type RiskInstance struct {
	Resource string
	IP       string
	Proof    map[string]any
}

// NewRiskConsoleOutputter creates a new console outputter for Risk types
func NewRiskConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &RiskConsoleOutputter{
		riskGroups: make(map[string][]model.Risk),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects risk items for grouped output
func (o *RiskConsoleOutputter) Output(v any) error {
	// Try to get a Janus Risk type
	janusRisk, ok := v.(model.Risk)
	if !ok {
		// Try as pointer
		janusRiskPtr, ok := v.(*model.Risk)
		if !ok {
			return nil // Not a Janus Risk, silently ignore
		}
		janusRisk = *janusRiskPtr
	}

	// Store the risk in the appropriate group
	o.riskGroups[janusRisk.Name] = append(o.riskGroups[janusRisk.Name], janusRisk)

	return nil
}

// Initialize is called when the outputter is initialized
func (o *RiskConsoleOutputter) Initialize() error {
	return nil
}

// Complete is called when the chain is complete - display all collected risks
func (o *RiskConsoleOutputter) Complete() error {
	return nil
}

// Params returns the parameters for this outputter
func (o *RiskConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}

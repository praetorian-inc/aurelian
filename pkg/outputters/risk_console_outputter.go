package outputters

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	janustypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/internal/message"
)

type RiskConsoleOutputter struct {
	*chain.BaseOutputter
	riskGroups map[string][]janustypes.Risk // Map to store risks grouped by name
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
		riskGroups: make(map[string][]janustypes.Risk),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects risk items for grouped output
func (o *RiskConsoleOutputter) Output(v any) error {
	// Try to get a Janus Risk type
	janusRisk, ok := v.(janustypes.Risk)
	if !ok {
		// Try as pointer
		janusRiskPtr, ok := v.(*janustypes.Risk)
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
	// Process all grouped risks
	for riskName, risks := range o.riskGroups {
		if len(risks) == 0 {
			continue
		}

		// Use the first risk for common information
		firstRisk := risks[0]

		// Format the severity for better readability
		severity := strings.ToUpper(firstRisk.Severity)

		// Create a formatted message header - only use colorized output for the header
		header := fmt.Sprintf("[%s] %s", severity, riskName)
		message.Success("%s", header)

		// Add description if available in metadata - use plain text
		if firstRisk.Metadata != nil {
			if desc, ok := firstRisk.Metadata["description"].(string); ok && desc != "" {
				fmt.Printf("Description: %s\n", desc)
			}
		}

		// List impacted services if available - use plain text
		if firstRisk.Metadata != nil {
			if services, ok := firstRisk.Metadata["impacted-services"]; ok {
				fmt.Printf("Impacted Services: %v\n", services)
			}
		}

		// Print each affected resource - use plain text
		fmt.Println("Affected Resources:")
		for _, risk := range risks {
			resourceInfo := "  - "
			if risk.DNS != "" {
				resourceInfo += risk.DNS
			}
			if risk.IP != "" {
				if risk.DNS != "" {
					resourceInfo += fmt.Sprintf(" (IP: %s)", risk.IP)
				} else {
					resourceInfo += fmt.Sprintf("IP: %s", risk.IP)
				}
			}
			fmt.Println(resourceInfo)

			// Add proof details if available - use plain text
			if len(risk.Proof) > 0 {
				for key, value := range risk.Proof {
					fmt.Printf("    %s: %v\n", key, value)
				}
			}
		}

		// Add metadata to debug log
		if len(firstRisk.Metadata) > 0 {
			slog.Debug("Risk metadata", "risk", riskName, "metadata", firstRisk.Metadata)
		}

		// Add a blank line between risk groups for better readability
		if len(o.riskGroups) > 1 {
			fmt.Println()
		}
	}

	return nil
}

// Params returns the parameters for this outputter
func (o *RiskConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}

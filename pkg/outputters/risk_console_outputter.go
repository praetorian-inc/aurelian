package outputters

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
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
	if len(o.riskGroups) == 0 {
		message.Info("No security risks found")
		return nil
	}

	// Display summary first
	totalRisks := 0
	for _, risks := range o.riskGroups {
		totalRisks += len(risks)
	}

	message.Section("=== Security Risk Summary ===")
	message.Info("Found %d security risks across %d categories", totalRisks, len(o.riskGroups))

	// Display each risk group
	for riskName, risks := range o.riskGroups {
		o.displayRiskGroup(riskName, risks)
	}

	return nil
}

// displayRiskGroup formats and displays a group of risks with the same name
func (o *RiskConsoleOutputter) displayRiskGroup(riskName string, risks []model.Risk) {
	if len(risks) == 0 {
		return
	}

	// Use the first risk for common properties
	firstRisk := risks[0]
	severity := o.formatSeverity(firstRisk.Severity())

	message.Section("%s %s (%d %s)",
		severity,
		strings.ToUpper(riskName),
		len(risks),
		o.pluralize("instance", len(risks)))

	// Display each instance
	for i, risk := range risks {
		o.displayRiskInstance(risk, i+1, len(risks))
	}
}

func (o *RiskConsoleOutputter) displayRiskInstance(risk model.Risk, instanceNum, totalInstances int) {
	instanceHeader := fmt.Sprintf("Instance %d/%d - Account: %s", instanceNum, totalInstances, risk.DNS)

	switch risk.Severity() {
	case "H", "TH": // TriageHigh
		message.Success("%s", instanceHeader)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	case "M", "TM": // TriageMedium
		message.Success("%s", instanceHeader)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	case "L", "TL": // TriageLow
		message.Success("%s", instanceHeader)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	default:
		message.Success("%s", instanceHeader)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	}
}

func (o *RiskConsoleOutputter) formatSeverity(severity string) string {
	switch severity {
	case "H", "TH":
		return "🔴 HIGH"
	case "M", "TM":
		return "🟡 MEDIUM"
	case "L", "TL":
		return "🟢 LOW"
	default:
		return fmt.Sprintf("⚪ UNKNOWN (%s)", severity)
	}
}

func (o *RiskConsoleOutputter) pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

// Params returns the parameters for this outputter
func (o *RiskConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}

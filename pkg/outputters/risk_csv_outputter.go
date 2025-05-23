package outputters

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	janustypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/internal/message"
)

type RiskCSVOutputter struct {
	*chain.BaseOutputter
	risks      []janustypes.Risk // List to store all risks
	outputFile string
}

// NewRiskCSVOutputter creates a new CSV outputter for Risk types
func NewRiskCSVOutputter(configs ...cfg.Config) chain.Outputter {
	o := &RiskCSVOutputter{
		risks:      []janustypes.Risk{},
		outputFile: "risks.csv",
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects risk items for CSV output
func (o *RiskCSVOutputter) Output(v any) error {
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

	// Store the risk
	o.risks = append(o.risks, janusRisk)

	return nil
}

// Initialize is called when the outputter is initialized
func (o *RiskCSVOutputter) Initialize() error {
	// Get output file from parameters
	outputFile, err := cfg.As[string](o.Arg("csvoutfile"))
	if err == nil && outputFile != "" {
		o.outputFile = outputFile
	}
	return nil
}

// Complete is called when the chain is complete - write all collected risks to CSV
func (o *RiskCSVOutputter) Complete() error {
	if len(o.risks) == 0 {
		slog.Info("No risks to write to CSV")
		return nil
	}

	// Create CSV file
	file, err := os.Create(o.outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	header := []string{
		"Name",
		"Severity",
		"DNS",
		"IP",
		"Description",
		"Impacted Services",
		"Proof",
		"Metadata",
	}

	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// Write each risk as a CSV row
	for _, risk := range o.risks {
		// Extract description and impacted services from metadata
		description := ""
		impactedServices := ""

		if risk.Metadata != nil {
			if desc, ok := risk.Metadata["description"].(string); ok {
				description = desc
			}

			if services, ok := risk.Metadata["impacted-services"]; ok {
				// Convert services to string
				servicesStr, err := formatAny(services)
				if err == nil {
					impactedServices = servicesStr
				}
			}
		}

		// Convert proof to string
		proofStr, err := formatMap(risk.Proof)
		if err != nil {
			proofStr = fmt.Sprintf("Error formatting proof: %v", err)
		}

		// Convert metadata to string
		metadataStr, err := formatMap(risk.Metadata)
		if err != nil {
			metadataStr = fmt.Sprintf("Error formatting metadata: %v", err)
		}

		// Create and write the CSV row
		row := []string{
			risk.Name,
			risk.Severity,
			risk.DNS,
			risk.IP,
			description,
			impactedServices,
			proofStr,
			metadataStr,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row: %w", err)
		}
	}

	message.Success("CSV output written to %s (%d risks)", o.outputFile, len(o.risks))
	return nil
}

// formatMap formats a map as a string (used for Proof and Metadata)
func formatMap(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	// Make the JSON string safe for CSV (replace commas, quotes, etc.)
	return strings.ReplaceAll(string(jsonBytes), "\"", "'"), nil
}

// formatAny formats any value as a string
func formatAny(v any) (string, error) {
	if v == nil {
		return "", nil
	}

	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// Make the JSON string safe for CSV (replace commas, quotes, etc.)
	return strings.ReplaceAll(string(jsonBytes), "\"", "'"), nil
}

// Params returns the parameters for this outputter
func (o *RiskCSVOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("csvoutfile", "file to write the CSV output to").WithDefault("risks.csv"),
	}
}

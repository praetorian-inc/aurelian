package aws

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsGaadFileLoader struct {
	*base.AwsReconLink
}

func NewAwsGaadFileLoader(configs ...cfg.Config) chain.Link {
	g := &AwsGaadFileLoader{}
	g.AwsReconLink = base.NewAwsReconLink(g, configs...)
	return g
}

func (g *AwsGaadFileLoader) Process(input any) error {
	gaadFile, err := cfg.As[string](g.Arg("gaad-file"))
	if err != nil {
		return fmt.Errorf("gaad-file parameter is required: %w", err)
	}

	if gaadFile == "" {
		return fmt.Errorf("gaad-file parameter cannot be empty")
	}

	// Read the GAAD file
	data, err := os.ReadFile(gaadFile)
	if err != nil {
		return fmt.Errorf("failed to read GAAD file '%s': %w", gaadFile, err)
	}

	// Parse as array first (matching account-auth-details module output format)
	var gaadArray []types.Gaad
	if err := json.Unmarshal(data, &gaadArray); err == nil && len(gaadArray) > 0 {
		// Send the GAAD data as NamedOutputData for consistent handling
		g.Send(outputters.NewNamedOutputData(gaadArray[0], "gaad-data"))
		g.Logger.Info(fmt.Sprintf("Successfully loaded GAAD data from %s", gaadFile))
		return nil
	}

	// Fallback: try parsing as single GAAD object
	var gaad types.Gaad
	if err := json.Unmarshal(data, &gaad); err != nil {
		return fmt.Errorf("failed to parse GAAD file '%s' as JSON (tried both array and single object): %w", gaadFile, err)
	}

	// Send the GAAD data
	g.Send(outputters.NewNamedOutputData(gaad, "gaad-data"))
	g.Logger.Info(fmt.Sprintf("Successfully loaded GAAD data from %s", gaadFile))
	return nil
}
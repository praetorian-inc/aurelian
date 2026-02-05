package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AwsGaadFileLoader struct {
	*base.NativeAWSLink
}

func NewAwsGaadFileLoader(args map[string]any) *AwsGaadFileLoader {
	return &AwsGaadFileLoader{
		NativeAWSLink: base.NewNativeAWSLink("gaad-file-loader", args),
	}
}

func (g *AwsGaadFileLoader) Process(ctx context.Context, input any) ([]any, error) {
	gaadFile := g.ArgString("gaad-file", "")
	if gaadFile == "" {
		return nil, fmt.Errorf("gaad-file parameter is required")
	}

	// Read the GAAD file
	data, err := os.ReadFile(gaadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read GAAD file '%s': %w", gaadFile, err)
	}

	// Parse as array first (matching account-auth-details module output format)
	var gaadArray []types.Gaad
	if err := json.Unmarshal(data, &gaadArray); err == nil && len(gaadArray) > 0 {
		// Return the GAAD data as NamedOutputData for consistent handling
		return []any{outputters.NewNamedOutputData(gaadArray[0], "gaad-data")}, nil
	}

	// Fallback: try parsing as single GAAD object
	var gaad types.Gaad
	if err := json.Unmarshal(data, &gaad); err != nil {
		return nil, fmt.Errorf("failed to parse GAAD file '%s' as JSON (tried both array and single object): %w", gaadFile, err)
	}

	// Return the GAAD data
	return []any{outputters.NewNamedOutputData(gaad, "gaad-data")}, nil
}

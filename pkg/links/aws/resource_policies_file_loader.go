package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AwsResourcePoliciesFileLoader struct {
	*base.NativeAWSLink
}

func NewAwsResourcePoliciesFileLoader(args map[string]any) *AwsResourcePoliciesFileLoader {
	return &AwsResourcePoliciesFileLoader{
		NativeAWSLink: base.NewNativeAWSLink("aws-resource-policies-file-loader", args),
	}
}

func (r *AwsResourcePoliciesFileLoader) Process(ctx context.Context, input any) ([]any, error) {
	resourcePoliciesFile := r.ArgString("resource-policies-file", "")
	if resourcePoliciesFile == "" {
		return nil, fmt.Errorf("resource-policies-file parameter is required")
	}

	// Read the resource policies file
	data, err := os.ReadFile(resourcePoliciesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource policies file '%s': %w", resourcePoliciesFile, err)
	}

	// Parse the file as array first (in case it was output from resource-policies module in array format)
	var resourcePoliciesArray []map[string]*types.Policy
	if err := json.Unmarshal(data, &resourcePoliciesArray); err == nil && len(resourcePoliciesArray) > 0 {
		// Take the first element if it's in array format
		r.Send(outputters.NewNamedOutputData(resourcePoliciesArray[0], "resource-policies"))
		slog.Info("Successfully loaded resource policies from array format", "file", resourcePoliciesFile, "count", len(resourcePoliciesArray[0]))
		return r.Outputs(), nil
	}

	// Parse as map[string]*types.Policy directly (expected format)
	var resourcePolicies map[string]*types.Policy
	if err := json.Unmarshal(data, &resourcePolicies); err != nil {
		return nil, fmt.Errorf("failed to parse resource policies file '%s' as JSON (tried both array and map format): %w", resourcePoliciesFile, err)
	}

	// Validate that it's not empty
	if len(resourcePolicies) == 0 {
		slog.Warn("Resource policies file contains no policies", "file", resourcePoliciesFile)
	}

	// Send the resource policies map
	r.Send(outputters.NewNamedOutputData(resourcePolicies, "resource-policies"))
	slog.Info("Successfully loaded resource policies", "file", resourcePoliciesFile, "count", len(resourcePolicies))
	return r.Outputs(), nil
}

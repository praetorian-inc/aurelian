package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type AzureConditionalAccessFileLoader struct {
	*base.NativeAzureLink
}

// ConditionalAccessPolicyCollection represents the metadata wrapper format
// containing multiple policies with collection metadata
type ConditionalAccessPolicyCollection struct {
	Metadata struct {
		CollectedAt string `json:"collectedAt"`
		Module      string `json:"module"`
		PolicyCount int    `json:"policyCount"`
		TenantId    string `json:"tenantId"`
	} `json:"metadata"`
	Policies []EnrichedConditionalAccessPolicy `json:"policies"`
}

func NewAzureConditionalAccessFileLoader(args map[string]any) *AzureConditionalAccessFileLoader {
	return &AzureConditionalAccessFileLoader{
		NativeAzureLink: base.NewNativeAzureLink("conditional-access-file-loader", args),
	}
}

func (l *AzureConditionalAccessFileLoader) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureConditionalAccessFile(),
	}
}

func (l *AzureConditionalAccessFileLoader) Process(ctx context.Context, input any) ([]any, error) {
	conditionalAccessFile := l.ArgString("conditional-access-file", "")

	// In chained mode, if file parameter is absent/empty, pass through input
	if conditionalAccessFile == "" {
		if input != nil {
			// Chained mode - pass through the input data
			l.Send(input)
			return l.Outputs(), nil
		}
		// Standalone mode (input is nil) - file parameter is required
		return nil, fmt.Errorf("conditional-access-file parameter cannot be empty in standalone mode")
	}

	// Read the conditional access policies file
	data, err := os.ReadFile(conditionalAccessFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read conditional access file '%s': %w", conditionalAccessFile, err)
	}

	// Try parsing as metadata wrapper format first (new format from conditional access collection)
	var policyCollections []ConditionalAccessPolicyCollection
	if err := json.Unmarshal(data, &policyCollections); err == nil && len(policyCollections) > 0 {
		// Collect all policies from all collections into a single array
		var allPolicies []EnrichedConditionalAccessPolicy
		for _, collection := range policyCollections {
			allPolicies = append(allPolicies, collection.Policies...)
		}

		if len(allPolicies) > 0 {
			// Send all policies together as one unit for holistic analysis
			l.Send(allPolicies)
			l.Logger().Info(fmt.Sprintf("Successfully loaded %d conditional access policies from %s", len(allPolicies), conditionalAccessFile))
		}
		return l.Outputs(), nil
	}

	// Parse the file as array (legacy format from conditional access collection)
	var conditionalAccessPoliciesArray []EnrichedConditionalAccessPolicy
	if err := json.Unmarshal(data, &conditionalAccessPoliciesArray); err == nil && len(conditionalAccessPoliciesArray) > 0 {
		// Send all policies together as one unit for holistic analysis
		l.Send(conditionalAccessPoliciesArray)
		l.Logger().Info(fmt.Sprintf("Successfully loaded %d conditional access policies from %s", len(conditionalAccessPoliciesArray), conditionalAccessFile))
		return l.Outputs(), nil
	}

	// Try parsing as single policy object
	var singlePolicy EnrichedConditionalAccessPolicy
	if err := json.Unmarshal(data, &singlePolicy); err != nil {
		return nil, fmt.Errorf("failed to parse conditional access file '%s' as JSON (tried both array and single policy format): %w", conditionalAccessFile, err)
	}

	// Send the single policy as an array for consistency in analysis
	l.Send([]EnrichedConditionalAccessPolicy{singlePolicy})
	l.Logger().Info(fmt.Sprintf("Successfully loaded 1 conditional access policy from %s", conditionalAccessFile))
	return l.Outputs(), nil
}
package azure

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AzureConditionalAccessFileLoader struct {
	*chain.Base
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

func NewAzureConditionalAccessFileLoader(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessFileLoader{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessFileLoader) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureConditionalAccessFile(),
	}
}

func (l *AzureConditionalAccessFileLoader) Process(input any) error {
	conditionalAccessFile, err := cfg.As[string](l.Arg("conditional-access-file"))
	
	// In chained mode, if file parameter is absent/empty, pass through input
	if err != nil || conditionalAccessFile == "" {
		if input != nil {
			// Chained mode - pass through the input data
			return l.Send(input)
		}
		// Standalone mode (input is nil) - file parameter is required
		if err != nil {
			return fmt.Errorf("conditional-access-file parameter is required in standalone mode: %w", err)
		}
		return fmt.Errorf("conditional-access-file parameter cannot be empty in standalone mode")
	}

	// Read the conditional access policies file
	data, err := os.ReadFile(conditionalAccessFile)
	if err != nil {
		return fmt.Errorf("failed to read conditional access file '%s': %w", conditionalAccessFile, err)
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
			l.Logger.Info(fmt.Sprintf("Successfully loaded %d conditional access policies from %s", len(allPolicies), conditionalAccessFile))
		}
		return nil
	}

	// Parse the file as array (legacy format from conditional access collection)
	var conditionalAccessPoliciesArray []EnrichedConditionalAccessPolicy
	if err := json.Unmarshal(data, &conditionalAccessPoliciesArray); err == nil && len(conditionalAccessPoliciesArray) > 0 {
		// Send all policies together as one unit for holistic analysis
		l.Send(conditionalAccessPoliciesArray)
		l.Logger.Info(fmt.Sprintf("Successfully loaded %d conditional access policies from %s", len(conditionalAccessPoliciesArray), conditionalAccessFile))
		return nil
	}

	// Try parsing as single policy object
	var singlePolicy EnrichedConditionalAccessPolicy
	if err := json.Unmarshal(data, &singlePolicy); err != nil {
		return fmt.Errorf("failed to parse conditional access file '%s' as JSON (tried both array and single policy format): %w", conditionalAccessFile, err)
	}

	// Send the single policy as an array for consistency in analysis
	l.Send([]EnrichedConditionalAccessPolicy{singlePolicy})
	l.Logger.Info(fmt.Sprintf("Successfully loaded 1 conditional access policy from %s", conditionalAccessFile))
	return nil
}
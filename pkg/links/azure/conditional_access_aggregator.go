package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// AzureConditionalAccessAggregatorLink collects both recon policies and LLM analysis into a single comprehensive output
type AzureConditionalAccessAggregatorLink struct {
	*base.NativeAzureLink
	policies []EnrichedConditionalAccessPolicy
	analysis *ConditionalAccessAnalysisResult
}

func NewAzureConditionalAccessAggregatorLink(args map[string]any) *AzureConditionalAccessAggregatorLink {
	return &AzureConditionalAccessAggregatorLink{
		NativeAzureLink: base.NewNativeAzureLink("conditional-access-aggregator", args),
		policies:        make([]EnrichedConditionalAccessPolicy, 0),
	}
}

func (l *AzureConditionalAccessAggregatorLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{}
}

func (l *AzureConditionalAccessAggregatorLink) Process(ctx context.Context, input any) ([]any, error) {
	switch v := input.(type) {
	case []EnrichedConditionalAccessPolicy:
		// Collect recon policy data
		l.policies = v

	case ConditionalAccessAnalysisResult:
		// Collect LLM analysis results
		l.analysis = &v

	case nil:
		// Handle case where analysis failed - analysis remains nil

	default:
		// Unknown input type - ignored
	}

	return l.Outputs(), nil
}

func (l *AzureConditionalAccessAggregatorLink) Complete(ctx context.Context) error {
	l.Logger().Info("Creating combined conditional access output", "policies", len(l.policies), "has_analysis", l.analysis != nil)

	// Create combined output structure
	combinedOutput := l.createCombinedOutput()

	// Add to outputs
	l.Send(combinedOutput)

	return nil
}

func (l *AzureConditionalAccessAggregatorLink) createCombinedOutput() map[string]any {
	// Get tenant ID for metadata
	tenantID, _ := l.getTenantID()

	// Determine if LLM analysis was enabled/successful
	llmEnabled := l.analysis != nil

	// Create comprehensive metadata
	metadata := map[string]any{
		"tenantId":             tenantID,
		"collection_time":      time.Now().Format(time.RFC3339),
		"data_type":            "azure_conditional_access_comprehensive",
		"policies_count":       len(l.policies),
		"llm_analysis_enabled": llmEnabled,
	}

	// Add analysis metadata if available
	if l.analysis != nil {
		metadata["analysis_timestamp"] = l.analysis.AnalysisTimestamp
		metadata["llm_provider"] = l.analysis.LLMProvider
		metadata["policy_set_id"] = l.analysis.PolicySetID
		metadata["observations_detected"] = len(l.analysis.ObservationsDetected)
	}

	// Create combined structure
	combinedOutput := map[string]any{
		"metadata": metadata,
		"policies": l.policies,
		"analysis": l.analysis, // Will be nil if LLM disabled/failed
	}

	return combinedOutput
}

// getTenantID retrieves the Azure tenant ID for metadata
func (l *AzureConditionalAccessAggregatorLink) getTenantID() (string, error) {
	// Get Azure credentials and create Graph client
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "unknown", err
	}

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return "unknown", err
	}

	// Get tenant info
	org, err := graphClient.Organization().Get(context.Background(), nil)
	if err != nil {
		return "unknown", err
	}

	if org != nil && org.GetValue() != nil && len(org.GetValue()) > 0 {
		if id := org.GetValue()[0].GetId(); id != nil {
			return *id, nil
		}
	}

	return "unknown", fmt.Errorf("no tenant ID available")
}

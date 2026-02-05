package azure

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type AzureConditionalAccessOutputFormatterLink struct {
	*base.NativeAzureLink
}

func NewAzureConditionalAccessOutputFormatterLink(args map[string]any) *AzureConditionalAccessOutputFormatterLink {
	return &AzureConditionalAccessOutputFormatterLink{
		NativeAzureLink: base.NewNativeAzureLink("conditional-access-output-formatter", args),
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureWorkerCount(),
		options.OutputDir(),
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) Process(ctx context.Context, input any) ([]any, error) {
	// Expect input to be []EnrichedConditionalAccessPolicy from resolver
	enrichedPolicies, ok := input.([]EnrichedConditionalAccessPolicy)
	if !ok {
		return nil, fmt.Errorf("expected []EnrichedConditionalAccessPolicy, got %T", input)
	}

	// Generate console output (directly to stdout, not sent through pipeline)
	l.generateConsoleOutput(enrichedPolicies)

	// Always send policies to next link in chain (LLM analyzer)
	// LLM analyzer will decide whether to process or pass through based on enable-llm-analysis parameter
	l.Send(enrichedPolicies)
	return l.Outputs(), nil
}

func (l *AzureConditionalAccessOutputFormatterLink) generateConsoleOutput(policies []EnrichedConditionalAccessPolicy) {
	// Print console table directly to stdout
	fmt.Printf("\nAzure Conditional Access Policies\n")
	fmt.Printf("| %-30s | %-15s | %-5s | %-6s | %-12s |\n",
		"Policy Name", "State", "Users", "Groups", "Applications")
	fmt.Printf("|%s|%s|%s|%s|%s|\n",
		"--------------------------------", "-----------------", "-------", "--------", "--------------")

	for _, policy := range policies {
		userCount := len(policy.ResolvedUsers)
		groupCount := len(policy.ResolvedGroups)
		appCount := len(policy.ResolvedApplications)

		// Truncate policy name if too long
		policyName := policy.DisplayName
		if len(policyName) > 30 {
			policyName = policyName[:27] + "..."
		}

		fmt.Printf("| %-30s | %-15s | %-5d | %-6d | %-12d |\n",
			policyName, l.formatPolicyState(policy.State), userCount, groupCount, appCount)
	}
	fmt.Printf("\nTotal policies: %d\n", len(policies))
	fmt.Printf("\nTip: Add --enable-llm-analysis --llm-api-key <key> to get AI-powered security analysis of these policies\n")
}

func (l *AzureConditionalAccessOutputFormatterLink) formatPolicyState(state string) string {
	switch state {
	case "enabled":
		return "Enabled"
	case "disabled":
		return "Disabled"
	case "enabledForReportingButNotEnforced":
		return "Report-only"
	default:
		return state
	}
}
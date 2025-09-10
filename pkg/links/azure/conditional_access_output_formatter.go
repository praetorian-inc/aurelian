package azure

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AzureConditionalAccessOutputFormatterLink struct {
	*chain.Base
}

func NewAzureConditionalAccessOutputFormatterLink(configs ...cfg.Config) chain.Link {
	l := &AzureConditionalAccessOutputFormatterLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureConditionalAccessOutputFormatterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureWorkerCount(),
		options.OutputDir(),
	}
}

func (l *AzureConditionalAccessOutputFormatterLink) Process(input any) error {
	// Expect input to be []EnrichedConditionalAccessPolicy from resolver
	enrichedPolicies, ok := input.([]EnrichedConditionalAccessPolicy)
	if !ok {
		return fmt.Errorf("expected []EnrichedConditionalAccessPolicy, got %T", input)
	}

	// Generate console output (directly to stdout, not sent through pipeline)
	l.generateConsoleOutput(enrichedPolicies)

	// Always send policies to next link in chain (LLM analyzer)
	// LLM analyzer will decide whether to process or pass through based on enable-llm-analysis parameter
	return l.Send(enrichedPolicies)
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
package enrichers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("virtual_machines_public_access", enrichVirtualMachinePublicAccess)
}

func enrichVirtualMachinePublicAccess(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	targetIPs := extractStringSlice(result.Properties, "publicIPs")
	if len(targetIPs) == 0 {
		return nil, nil
	}

	openPorts := extractStringSlice(result.Properties, "openPorts")
	if len(openPorts) == 0 {
		return nil, nil
	}

	portList := strings.Join(openPorts, ",")
	targetIPList := strings.Join(targetIPs, " ")

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("nmap -sS -Pn -p %s -T5 %s", portList, targetIPList),
		Description:               "Network scan of the virtual machine on discovered open ports",
		ExpectedOutputDescription: "Detailed service information for open ports on the VM",
		ActualOutput:              "Manual execution required",
	}

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}

// extractStringSlice extracts a string slice from a properties map.
// Handles both []any (direct) and string (JSON-encoded from ARG tostring(make_set(...))).
func extractStringSlice(props map[string]any, key string) []string {
	val, ok := props[key]
	if !ok {
		return nil
	}

	// Direct []any slice (standard case).
	if slice, ok := val.([]any); ok {
		var result []string
		for _, v := range slice {
			if s, ok := v.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	}

	// JSON string from ARG tostring(make_set(...)).
	if s, ok := val.(string); ok && strings.HasPrefix(s, "[") {
		var result []string
		if err := json.Unmarshal([]byte(s), &result); err == nil {
			var filtered []string
			for _, v := range result {
				if v != "" {
					filtered = append(filtered, v)
				}
			}
			return filtered
		}
	}

	return nil
}

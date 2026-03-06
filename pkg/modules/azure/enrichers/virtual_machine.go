package enrichers

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("virtual_machines_public_access", enrichVirtualMachinePublicAccess)
}

func enrichVirtualMachinePublicAccess(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	// Extract public IPs from properties
	var targetIPs []string
	if publicIPs, ok := result.Properties["publicIPs"].([]any); ok {
		for _, ip := range publicIPs {
			if ipStr, ok := ip.(string); ok && ipStr != "" {
				targetIPs = append(targetIPs, ipStr)
			}
		}
	}
	if len(targetIPs) == 0 {
		return nil, nil
	}

	// Extract open ports from properties
	var openPorts []string
	if ports, ok := result.Properties["openPorts"].([]any); ok {
		for _, port := range ports {
			if portStr, ok := port.(string); ok && portStr != "" {
				openPorts = append(openPorts, portStr)
			}
		}
	}
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

package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// VirtualMachineEnricher implements enrichment for virtual machines
type VirtualMachineEnricher struct{}

func (v *VirtualMachineEnricher) CanEnrich(templateID string) bool {
	return templateID == "virtual_machines_public_access"
}

func (v *VirtualMachineEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Get public IPs from the resource
	ips := make([]string, 0)
	if publicIPs, ok := resource.Properties["publicIPs"].([]any); ok {
		for _, ip := range publicIPs {
			if ipStr, ok := ip.(string); ok && ipStr != "" {
				ips = append(ips, ipStr)
			}
		}
	}
	if len(ips) == 0 {
		return commands
	}

	// Filter out empty IPs and create target list
	var targetIPs []string
	for _, ip := range ips {
		if ip != "" {
			targetIPs = append(targetIPs, ip)
		}
	}

	if len(targetIPs) == 0 {
		return commands
	}

	// Get open ports from ARG scan results
	openPorts := []string{}
	if ports, ok := resource.Properties["openPorts"].([]any); ok {
		for _, port := range ports {
			if portStr, ok := port.(string); ok && portStr != "" {
				openPorts = append(openPorts, portStr)
			}
		}
	}

	// Only add nmap command if there are open ports to scan
	if len(openPorts) == 0 {
		return commands
	}

	// Create port list for nmap (comma-separated)
	portList := strings.Join(openPorts, ",")

	// Create target IP list for nmap (space-separated)
	targetIPList := strings.Join(targetIPs, " ")

	// Add nmap command for network scanning using specific ports
	nmapCommand := Command{
		Command:                   fmt.Sprintf("nmap -sS -Pn -p %s -T5 %s", portList, targetIPList),
		Description:               "Network scan of the virtual machine on discovered open ports",
		ExpectedOutputDescription: "Detailed service information for open ports on the VM",
		ActualOutput:              "Manual execution required",
	}
	commands = append(commands, nmapCommand)

	return commands
}

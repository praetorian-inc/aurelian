package enricher

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// VirtualMachineEnricher implements enrichment for virtual machines
type VirtualMachineEnricher struct{}

func (v *VirtualMachineEnricher) CanEnrich(templateID string) bool {
	return templateID == "virtual_machines_public" || templateID == "virtual_machines_all"
}

func (v *VirtualMachineEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract VM name and location
	vmName := resource.Name
	location := resource.Region

	if vmName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "No VM name found",
			ActualOutput: "Error: VM name is empty",
		})
		return commands
	}

	// Add nmap command for network scanning
	nmapCommand := Command{
		Command:                   fmt.Sprintf("nmap -sS -O -A %s", vmName),
		Description:               "Network scan of the virtual machine",
		ExpectedOutputDescription: "Open ports and services running on the VM",
		ActualOutput:              "Manual execution required",
	}
	commands = append(commands, nmapCommand)

	// Add SSH connection test if applicable
	if location != "" {
		sshCommand := Command{
			Command:                   fmt.Sprintf("ssh -o ConnectTimeout=10 azureuser@%s.%s.cloudapp.azure.com", vmName, location),
			Description:               "Test SSH connectivity to the VM",
			ExpectedOutputDescription: "Connection success/failure, authentication method",
			ActualOutput:              "Manual execution required",
		}
		commands = append(commands, sshCommand)
	}

	return commands
}

package compute

import (
	"context"
	"fmt"
	"log/slog"
	"path"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
)

type GcpComputePublicHostChecker struct {
	*base.GcpReconLink
	computeService *compute.Service
}

func NewGcpComputePublicHostChecker(configs ...cfg.Config) chain.Link {
	g := &GcpComputePublicHostChecker{}
	g.GcpReconLink = base.NewGcpReconLink(g, configs...)
	return g
}

func (g *GcpComputePublicHostChecker) Initialize() error {
	if err := g.GcpReconLink.Initialize(); err != nil {
		return err
	}

	var err error
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}

	return nil
}

func (g *GcpComputePublicHostChecker) Process(instance tab.CloudResource) error {
	if instance.ResourceType != tab.GCPResourceInstance {
		slog.Debug("Skipping non-instance resource", "resourceType", instance.ResourceType)
		return nil
	}

	// zone, ok := instance.Properties["zone"].(string)
	// if !ok {
	// 	return fmt.Errorf("instance %s missing zone information", instance.Name)
	// }

	// freshInstance, err := g.computeService.Instances.Get(instance.AccountId(), zone, instance.Identifier()).Do()
	// if err != nil {
	// 	slog.Error("Failed to get instance details", "error", err, "project", instance.AccountId, "zone", zone, "instance", instance.Identifier)
	// 	return nil
	// }

	// publicIPs := g.extractPublicIPs(freshInstance)

	// if len(publicIPs) > 0 {
	// 	slog.Info("Found public compute instance",
	// 		"project", instance.AccountId,
	// 		"zone", zone,
	// 		"instance", instance.Identifier,
	// 		"publicIPs", publicIPs)

	// 	enrichedResource := &types.EnrichedResourceDescription{
	// 		Identifier: instance.Identifier,
	// 		TypeName:   string(tab.GCPResourceInstance),
	// 		Region:     instance.Region,
	// 		AccountId:  instance.AccountId,
	// 		Properties: g.buildPublicInstanceProperties(freshInstance, publicIPs),
	// 	}

	// 	g.Send(enrichedResource)
	// } else {
	// 	slog.Debug("Instance has no public IP", "project", instance.AccountId, "instance", instance.Identifier)
	// }

	return nil
}

func (g *GcpComputePublicHostChecker) extractPublicIPs(instance *compute.Instance) []string {
	var publicIPs []string

	for _, networkInterface := range instance.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if accessConfig.NatIP != "" {
				publicIPs = append(publicIPs, accessConfig.NatIP)
			}
		}
	}

	return publicIPs
}

func (g *GcpComputePublicHostChecker) buildPublicInstanceProperties(instance *compute.Instance, publicIPs []string) map[string]any {
	zone := ""
	if instance.Zone != "" {
		zone = path.Base(instance.Zone)
	}

	properties := map[string]any{
		"id":                      fmt.Sprintf("%d", instance.Id),
		"name":                    instance.Name,
		"zone":                    zone,
		"machineType":             path.Base(instance.MachineType),
		"status":                  instance.Status,
		"selfLink":                instance.SelfLink,
		"creationTimestamp":       instance.CreationTimestamp,
		"publicIPs":               publicIPs,
		"hasPublicAccess":         true,
		"publicNetworkInterfaces": g.extractPublicNetworkDetails(instance),
	}

	if instance.Labels != nil && len(instance.Labels) > 0 {
		properties["labels"] = instance.Labels
	}

	if len(instance.ServiceAccounts) > 0 {
		serviceAccounts := make([]map[string]any, 0, len(instance.ServiceAccounts))
		for _, sa := range instance.ServiceAccounts {
			serviceAccounts = append(serviceAccounts, map[string]any{
				"email":  sa.Email,
				"scopes": sa.Scopes,
			})
		}
		properties["serviceAccounts"] = serviceAccounts
	}

	if instance.Metadata != nil && len(instance.Metadata.Items) > 0 {
		metadata := make(map[string]string)
		for _, item := range instance.Metadata.Items {
			if item.Value != nil {
				metadata[item.Key] = *item.Value
			}
		}
		if len(metadata) > 0 {
			properties["metadata"] = metadata
		}
	}

	if instance.Tags != nil && len(instance.Tags.Items) > 0 {
		properties["networkTags"] = instance.Tags.Items
	}

	if len(instance.Disks) > 0 {
		disks := make([]map[string]any, 0, len(instance.Disks))
		for _, disk := range instance.Disks {
			diskInfo := map[string]any{
				"deviceName": disk.DeviceName,
				"boot":       disk.Boot,
				"type":       disk.Type,
				"mode":       disk.Mode,
			}
			if disk.Source != "" {
				diskInfo["source"] = path.Base(disk.Source)
			}
			disks = append(disks, diskInfo)
		}
		properties["disks"] = disks
	}

	return properties
}

func (g *GcpComputePublicHostChecker) extractPublicNetworkDetails(instance *compute.Instance) []map[string]any {
	var publicInterfaces []map[string]any

	for _, networkInterface := range instance.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if accessConfig.NatIP != "" {
				interfaceDetails := map[string]any{
					"network":          path.Base(networkInterface.Network),
					"subnetwork":       path.Base(networkInterface.Subnetwork),
					"privateIP":        networkInterface.NetworkIP,
					"publicIP":         accessConfig.NatIP,
					"accessConfigName": accessConfig.Name,
					"accessConfigType": accessConfig.Type,
				}

				if accessConfig.ExternalIpv6 != "" {
					interfaceDetails["externalIPv6"] = accessConfig.ExternalIpv6
				}

				publicInterfaces = append(publicInterfaces, interfaceDetails)
			}
		}
	}

	return publicInterfaces
}
